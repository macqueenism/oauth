## Oauth2 with Go using gorilla sessions

#### Libraries
`go get golang.org/x/oauth2 cloud.google.com/go/compute/metadata github.com/gorilla/sessions github.com/gorilla/mux`

#### Setup
Go to google developer console (https://console.developers.google.com/) and start a new project.
Once in the new project, in the `product and services` menu select `APIs and services` then `credentials`.

Click `Create Credentials` and `OAuth client id`.
You will have to set up the details for your web application by giving it a name and setting authorised origins and redirect uris.
These can be changed later but make sure to use `http://127.0.0.1:<your_port>` instead of `localhost`.

Once complete you will get a `clientID` and `clientSecret`. Fill out these values in the `creds.json` file in the main directory.

Once these are in place, run the application with the command: `go run main.go`.