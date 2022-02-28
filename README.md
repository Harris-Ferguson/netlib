# netlib
A small C socket networking library built for a Computer Networks course to help me get my assignments done quicker. 

The messy POSIX socket library stuff is all abstracted away, you only have to interact with file decsriptors and the addrinfo and sockaddr structs, however I am
planning add another layer of abstraction around those functions to make the library a little easier to use without mucking around in the sockets API for structs. 
