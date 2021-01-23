class MethodId(object):
    """
    Information about a method in a dex file.
    """

    def __init__(self, address, dexindex, classname, methodname, descriptor, is_import=False):
        self.address = address
        self.dexindex = dexindex
        self.classname = classname
        self.methodname = methodname
        self.descriptor = descriptor
        self.is_import = is_import

    @property
    def is_android_api(self):
        # Packages found at https://developer.android.com/reference/packages
        api_list = ['Landroid/', 'Lcom/google/android/', 'Ldalvik/', 'Ljava/', 'Ljavax/',
                    'Ljunit/', 'Lorg/apache/', 'Lorg/json/', 'Lorg/w3c/', 'Lorg/xml/', 'Lorg/xmlpull/']

        for api_prefix in api_list:
            if self.classname.startswith(api_prefix):
                return True

        return False

    def __repr__(self):
        return f'<MethodId-address:{self.address} dexindex:{self.dexindex}, classname:{self.classname}, methodname:{self.methodname}, descriptor:{self.descriptor}>'

    def __eq__(self, obj):
        return isinstance(obj,
                          MethodId) and obj.address == self.address and obj.classname == self.classname and obj.methodname == self.methodname and obj.descriptor == self.descriptor

    def __hash__(self):
        return hash(self.address) ^ hash(self.classname) ^ hash(self.methodname) ^ hash(self.descriptor)
