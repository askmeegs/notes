# 📝 notes

A minimal Notes server for storing text-only thoughts, etc. Uses [Google Cloud Firestore](https://cloud.google.com/firestore/). 

All requests must have a valid JWT (or cookie) which can be obtained by `POST /login`, using valid creds. 

**NOTE:** This server is only for demo purposes. JWTs alone are not a secure choice for end-user authentication in production.

## Endpoints 

- Create note: (`POST /notes`) 
- Get all notes (`GET /notes`)
- Get random note (`GET /notes/random)`

## Running in Google Kubernetes Engine  

### Prerequisites 

- GCP project with billing enabled
- A running GKE cluster in your project 
- Firestore API enabled for your project, with a database, `notesdb`, and an empty collection in that DB, called `notes` 
- A domain (to serve managed SSL certs)

### Steps 

1. Fork or clone this repo 
2. Build Docker image from source:
```
docker build -t <your-repo>:<tag> .
```
3. Push the docker image: 
```
docker push <your-repo>:<tag>
```
4. Update `kubernetes/deployment.yaml`'s `image` (line 24) with your Docker image 
5. Follow instructions [here](https://cloud.google.com/kubernetes-engine/docs/how-to/managed-certs#creating_an_ingress_with_a_managed_certificate) to create a GCP static IP address named `example-ip-address`. 
6. Update `kubernetes/managed-cert.yaml` with `domains: <your-domain-name>`
7. Get a service account private key for Firestore: [go to](https://console.cloud.google.com/iam-admin/serviceaccounts) the Google Cloud Platform Console > IAM & Admin > Service Accounts. Generate a private key, then download it as JSON, `service-account.json`  
8. Create a Kubernetes secret, `firestore-key`, from the service account JSON:
```
kubectl create secret generic firestore-key --from-file=./service-account.json
```
9. Create a second Kubernetes secret with your desired Notes Server credentials: 

```
kubectl create secret generic notes-secret --from-literal=username=<YOUR_USERNAME> --from-literal=password=<YOUR_PASSWORD> --from-literal=signkey=<YOUR_JWT_SIGN_KEY>
```

10. Apply Kubernetes manifests to the cluster. This will create the SSL managed certs for your domain name, an Ingress (for the static IP you created), and a Service/Deployment for the notes server. 

```
kubectl apply -f kubernetes/
```