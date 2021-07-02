class MethodId(object):
    """
    Information about a method in a dex file.
    """

    def __init__(
        self,
        address,
        dexindex,
        classname,
        methodname,
        descriptor,
        is_import=False,
    ):
        self.address = address
        self.dexindex = dexindex
        self.classname = classname
        self.methodname = methodname
        self.descriptor = descriptor
        self.is_import = is_import

    @property
    def is_android_api(self):
        # Packages found at https://developer.android.com/reference/packages
        api_list = [
            "Landroid/",
            "Lcom/google/android/",
            "Ldalvik/",
            "Ljava/",
            "Ljavax/",
            "Ljunit/",
            "Lorg/apache/",
            "Lorg/json/",
            "Lorg/w3c/",
            "Lorg/xml/",
            "Lorg/xmlpull/",
        ]

        for api_prefix in api_list:
            if self.classname.startswith(api_prefix):
                return True

        return False

    def __repr__(self):
        return f"<MethodId-address:{self.address} dex:{self.dexindex}, class:{self.classname}, method:{self.methodname}, descriptor:{self.descriptor}>"

    def __eq__(self, obj):
        return (
            isinstance(obj, MethodId)
            and obj.classname == self.classname
            and obj.methodname == self.methodname
            and obj.descriptor == self.descriptor
        )

    def __lt__(self, obj):
        return self.address < obj.address

    def __gt__(self, obj):
        return self.address < obj.address

    def __hash__(self):
        return (
            hash(self.classname)
            ^ hash(self.methodname)
            ^ hash(self.descriptor)
        )

    def __str__(self) -> str:
        return f"{self.classname}->{self.methodname} {self.descriptor}"
