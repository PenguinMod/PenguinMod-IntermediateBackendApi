DB File: `users.json`

```js
{
    // a random ID, different for each account
    // the account should be stored in the DB with this ID as the key
    "id": "821497532",

    // Username
    "name": "Username",

    // the salt for the password, will not be set for accounts that dont need a password
    // read the Notes section for more info
    "salt": "Password Salt",

    // the method this account uses for login, 0 for email, 1 for scratch, etc
    // ideally an Enum file should be made for this so its not a magic number all the time in the code
    "method": 0,

    // on login we should create a random token and put it here,
    // and on signout delete this token
    // this is to avoid checking the password or auth method for each endpoint, just check this token
    "token": "Account Token",

    // a timestamp in milliseconds when this token should expire,
    // we can expire tokens each time the server restarts
    "expiration": 1707965163000,
}
```

## Notes
Passwords should be stored with something similar to or the same as this method:
https://youtu.be/8ZtInClXe1Q?si=pp5JZBbn9pBvVUOk&t=432