def createHTTPHeader(path, host):
    return "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"