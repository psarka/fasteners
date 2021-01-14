import multiprocessing


def tester(command_q, result_q):
    while True:
        op, cmd = command_q.get()
        try:
            if op == 'terminate':
                break
            if op == 'exec':
                exec(cmd)
                result_q.put((0, None))
            if op == 'eval':
                res = eval(cmd)
                result_q.put((0, res))
        except Exception as e:
            result_q.put((1, e))


class Tester:

    def __enter__(self):
        self.command_q = multiprocessing.Queue()
        self.result_q = multiprocessing.Queue()
        self.p = multiprocessing.Process(target=tester, args=(self.command_q, self.result_q))
        self.p.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.command_q.put(('terminate', ''))
        self.command_q.close()
        self.result_q.close()
        # self.p.join() TODO

    def exec(self, command, timeout=1):
        self.command_q.put(('exec', command))
        exception, res = self.result_q.get(timeout=timeout)
        if exception:
            raise res

    def eval(self, command, timeout=1):
        self.command_q.put(('eval', command))
        exception, res = self.result_q.get(block=True, timeout=timeout)
        if exception:
            self.close()
            raise res
        else:
            return res

    def close(self):
        self.command_q.put(('terminate', ''))
        self.command_q.close()
        self.result_q.close()
        self.p.join()
