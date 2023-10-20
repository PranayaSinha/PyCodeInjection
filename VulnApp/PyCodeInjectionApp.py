#!/usr/bin/env python3

"""
Authors: Seth Art (sethsec@gmail.com, @sethsec), Charlie Worrell (@decidedlygray, https://keybase.io/decidedlygray)
Purpose: Web application intentionally vulnerable to Python Code Injection

WARNING: This application is intentionally vulnerable and should not be used in a production environment or for any actual security purpose. The use of 'eval' is dangerous as it allows code execution.
"""

import web
import io
import sys


urls = (
    '/', 'index',
    '/pyinject', 'pyinject'
)

render = web.template.render('templates/')
app = web.application(urls, globals())


class index:
    def GET(self):
        return "Hello World. Go to /pyinject for the fun"

    def POST(self):
        return "Hello World. Go to /pyinject for the fun"


class pyinject:
    def evaluate_code(self, code):
        """
        This method is a security risk and is used only for demonstration purposes. 
        It evaluates the Python code contained in the provided string.
        """
        eval_output = ''
        stdout = sys.stdout  # Save the original stdout
        sys.stdout = reportSIO = io.StringIO()

        try:
            result = eval(code)  # This is a security risk
            if result:
                eval_output = str(result)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            reportStr = reportSIO.getvalue()
            sys.stdout = stdout  # Restore the original stdout

            return str(reportStr) + eval_output

    def process_input(self, method):
        """
        Process the input based on the HTTP method (POST or GET).
        """
        eval_output = ''
        try:
            get_input = web.input()
            params = ['param1', 'param2']
            cookie1 = web.cookies().get('c1')

            if not cookie1:
                web.setcookie('c1', 'exploit_me', expires="", domain=None, secure=False)

            for param in params:
                if param in get_input:
                    eval_output += self.evaluate_code(get_input[param])

            if cookie1:
                eval_output += self.evaluate_code(str(cookie1))

            return render.index(eval_output)
        except Exception as error:
            print(f"An error occurred: {error}")
            return error

    def POST(self):
        return self.process_input(method='POST')

    def GET(self):
        return self.process_input(method='GET')


if __name__ == "__main__":
    app.run()
