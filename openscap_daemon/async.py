# Copyright 2015 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# openscap-daemon is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2.1 of the License, or
# (at your option) any later version.
#
# openscap-daemon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with openscap-daemon.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Martin Preisler <mpreisle@redhat.com>

import threading
import logging
import Queue


class Status(object):
    """This enum describes status of async actions. Calls can be pending,
    processing or done. When actions are done they are waiting for the caller
    to collect the results and then they are deleted entirely.
    """

    PENDING = 0
    PROCESSING = 1
    DONE = 2
    UNKNOWN = 3

    @staticmethod
    def from_string(status):
        if status == "pending":
            return Status.PENDING
        elif status == "processing":
            return Status.PROCESSING
        elif status == "done":
            return Status.DONE

        return Status.UNKNOWN

    @staticmethod
    def to_string(status):
        if status == Status.PENDING:
            return "pending"
        elif status == Status.PROCESSING:
            return "processing"
        elif status == Status.DONE:
            return "done"

        return "unknown"


class AsyncAction(object):
    def run(self):
        pass

    def cancel(self):
        pass


class AsyncLambdaAction(AsyncAction):
    def __init__(self, run, desc):
        self.run = run
        self.desc = desc

    def run(self):
        self.run()

    def __str__(self):
        return self.desc


class AsyncManager(object):
    """Allows the user to enqueue asynchronous actions, gives the user a token
    they can poll as often as they like and check status of the actions.

    This is necessary to run many tasks in parallel and is necessary to make
    the dbus API work smoothly. User calling dbus methods doesn't expect them
    to take hours to finish. The calls themselves need to finish in seconds.
    To make it work with OpenSCAP evaluations that regularly take tens of
    minutes we create a task by the dbus call and then poll it.
    """

    def _worker_main(self, worker_id):
        while True:
            priority, token, action = self.queue.get(True)

            logging.debug(
                "Worker %i starting action from the priority queue. "
                "priority=%i, token=%i, action='%s'" %
                (worker_id, priority, token, action)
            )

            with self.actions_lock:
                self.status[token] = Status.PROCESSING

            action.run()

            self.queue.task_done()
            with self.actions_lock:
                self.status[token] = Status.DONE

            threading._sleep(1)

    def __init__(self, workers=0):
        self.queue = Queue.PriorityQueue()

        if workers == 0:
            try:
                import multiprocessing
                workers = multiprocessing.cpu_count()

            except NotImplementedError:
                workers = 4

        self.workers = []

        for i in xrange(workers):
            worker = threading.Thread(
                name="AsyncManager worker (%i out of %i)" % (i, workers),
                target=AsyncManager._worker_main,
                args=(self, i)
            )
            self.workers.append(worker)
            worker.start()

        self.last_token = 0
        self.actions_lock = threading.Lock()
        self.status = {}

        logging.debug("Initialized AsyncManager, %i workers" % (len(self.workers)))

    def _allocate_token(self):
        with self.actions_lock:
            ret = self.last_token + 1
            self.last_token = ret
            self.status[ret] = Status.UNKNOWN

        return ret

    def enqueue(self, action, priority=0):
        token = self._allocate_token()
        assert(token not in self.status)

        with self.actions_lock:
            self.status[token] = Status.PENDING
            self.queue.put((priority, token, action))

        logging.debug("AsyncManager enqueued action '%s' with token %i" %
                      (action, token))
        return token

    def cancel(self, token):
        raise NotImplementedError()



