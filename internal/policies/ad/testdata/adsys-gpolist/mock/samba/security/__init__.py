def access_check(secdesc, token, flag):
    if secdesc.secdesc == "FAILED":
        raise RuntimeError("access_check() failed requested")
