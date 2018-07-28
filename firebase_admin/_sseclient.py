"""SSEClient module to handle streaming of realtime changes on the database
to the firebase-admin-sdk
"""

import re
import time
import warnings
import six
import requests


# Technically, we should support streams that mix line endings.  This regex,
# however, assumes that a system will provide consistent line endings.
end_of_field = re.compile(r'\r\n\r\n|\r\r|\n\n')


class KeepAuthSession(requests.Session):
    """A session that does not drop Authentication on redirects between domains"""
    def rebuild_auth(self, prepared_request, response):
        pass


class SSEClient(object):
    """SSE Client Class"""

    def __init__(self, url, session, last_id=None, retry=3000, **kwargs):
        """Initialize the SSEClient
        Args:
          url: the url to connect to
          session: the requests.session()
          last_id: optional id
          retry: the interval in ms
          **kwargs: extra kwargs will be sent to requests.get
        """
        self.should_connect = True
        self.url = url
        self.last_id = last_id
        self.retry = retry
        self.running = True
        self.session = session
        self.requests_kwargs = kwargs

        headers = self.requests_kwargs.get('headers', {})
        # The SSE spec requires making requests with Cache-Control: nocache
        headers['Cache-Control'] = 'no-cache'
        # The 'Accept' header is not required, but explicit > implicit
        headers['Accept'] = 'text/event-stream'

        self.requests_kwargs['headers'] = headers

        # Keep data here as it streams in
        self.buf = u''

        self._connect()

    def close(self):
        """Close the SSE Client instance"""
        # TODO: check if AttributeError is needed to catch here
        self.should_connect = False
        self.running = False
        self.retry = 0
        self.resp.close()
        #  self.resp.raw._fp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        #  self.resp.raw._fp.fp.raw._sock.close()


    def _connect(self):
        """connects to the server using requests"""
        if self.should_connect and self.running:
            success = False
            while not success:
                if self.last_id:
                    self.requests_kwargs['headers']['Last-Event-ID'] = self.last_id
                # Use session if set.  Otherwise fall back to requests module.
                self.requester = self.session or requests
                self.resp = self.requester.get(self.url, stream=True, **self.requests_kwargs)

                self.resp_iterator = self.resp.iter_content(decode_unicode=True)

                # TODO: Ensure we're handling redirects.  Might also stick the 'origin'
                # attribute on Events like the Javascript spec requires.
                self.resp.raise_for_status()
                success = True
        else:
            raise StopIteration()

    def _event_complete(self):
        """Checks if the event is completed by matching regular expression

        Returns:
           boolean: True if the regex matched meaning end of event, else False
        """
        return re.search(end_of_field, self.buf) is not None

    def __iter__(self):
        return self

    def __next__(self):
        while not self._event_complete():
            try:
                nextchar = next(self.resp_iterator)
                self.buf += nextchar
            except (StopIteration, requests.RequestException):
                time.sleep(self.retry / 1000.0)
                self._connect()


                # The SSE spec only supports resuming from a whole message, so
                # if we have half a message we should throw it out.
                head, sep, tail = self.buf.rpartition('\n')
                self.buf = head + sep
                continue

        split = re.split(end_of_field, self.buf)
        head = split[0]
        tail = "".join(split[1:])

        self.buf = tail
        msg = Event.parse(head)

        if msg.data == "credential is no longer valid":
            self._connect()
            return None

        if msg.data == 'null':
            return None

        # If the server requests a specific retry delay, we need to honor it.
        if msg.retry:
            self.retry = msg.retry

        # last_id should only be set if included in the message.  It's not
        # forgotten if a message omits it.
        if msg.event_id:
            self.last_id = msg.event_id

        return msg

    if six.PY2:
        next = __next__


class Event(object):
    """Event class to handle the events fired by SSE"""

    sse_line_pattern = re.compile('(?P<name>[^:]*):?( ?(?P<value>.*))?')

    def __init__(self, data='', event='message', event_id=None, retry=None):
        self.data = data
        self.event = event
        self.event_id = event_id
        self.retry = retry

    @classmethod
    def parse(cls, raw):
        """Given a possibly-multiline string representing an SSE message, parse it
        and return a Event object.

        Args:
          raw: the raw data to parse

        Returns:
          Event: newly intialized Event() object with the parameters  initialized
        """
        msg = cls()
        for line in raw.split('\n'):
            match = cls.sse_line_pattern.match(line)
            if match is None:
                # Malformed line.  Discard but warn.
                warnings.warn('Invalid SSE line: "%s"' % line, SyntaxWarning)
                continue

            name = match.groupdict()['name']
            value = match.groupdict()['value']
            if name == '':
                # line began with a ":", so is a comment.  Ignore
                continue

            if name == 'data':
                # If we already have some data, then join to it with a newline.
                # Else this is it.
                if msg.data:
                    msg.data = '%s\n%s' % (msg.data, value)
                else:
                    msg.data = value
            elif name == 'event':
                msg.event = value
            elif name == 'id':
                msg.event_id = value
            elif name == 'retry':
                msg.retry = int(value)

        return msg

    def __str__(self):
        return self.data
