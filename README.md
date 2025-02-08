# share-setup-download
Go Utility to setup a folder structure used on my file sharing platform. The utility creates a folder using the provided username and stores a file called hash.txt with the bcrypt hash of the provided password. 

#Build instructions
set a tag on git, for example v0.0.8 and push it to the repo
run 'go install github.com/juandid/share-setup-download@v0.0.8'
this will install the executable on your machine and you can use it as binary if available in the PATH
