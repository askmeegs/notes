FROM golang

ADD . $GOPATH/src/github.com/askmeegs/notes

# Build 
RUN go install github.com/askmeegs/notes

# Run the server binary on container start 
ENTRYPOINT /go/bin/notes

# listen on 8080 
EXPOSE 8080