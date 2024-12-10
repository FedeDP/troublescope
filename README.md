# troublescope

This is a Falco plugin that exposes Falco proc tree as a FuseFS.  
It can be useful to debug weird proc tree issues.

Also, a `diagnostic` event gets generated every time Falco proc tree diverges from real proc. 
