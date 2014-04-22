def make_utf8(*args):
    rv = []
    for arg in args:
        if isinstance(arg, bytes):
            rv.append(arg)
        else:
            rv.append(arg.encode('utf-8'))
    if len(rv) == 1:
        return rv[0]
    else:
        return rv
