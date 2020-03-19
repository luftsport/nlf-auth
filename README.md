# nlf-auth

An Oauth2 compliant server and client, proxy chaining NIF's Buypass OIDC login.

### Install

```
git clone https://github.com/luftsport/nlf-auth.git
virtualenv nlf-auth
cd nlf-auth/
source bin/activate
pip install -r requirements.txt
python run.py
```

Note the dependency on [nif-api](https://github.com/luftsport/nif-api) and if needed install manually:
```
pip install git+https://github.com/luftsport/nif-api.git
```


### Notes

- OIDC support from 2.x
- The 1.x tree contains the legacy passbuy version using [nif-tools](https://github.com/luftsport/nif-tools)
