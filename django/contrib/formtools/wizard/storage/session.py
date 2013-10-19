from django.contrib.formtools.wizard import storage


class SessionStorage(storage.BaseStorage):

    def __init__(self, *args, **kwargs):
        super(SessionStorage, self).__init__(*args, **kwargs)
        if self.prefix not in self.request.session:
            self.init_data()

    @property
    def data(self):
        self.request.session.modified = True
        return self.request.session[self.prefix]

    @data.setter
    def data(self, value):
        self.request.session[self.prefix] = value
        self.request.session.modified = True
