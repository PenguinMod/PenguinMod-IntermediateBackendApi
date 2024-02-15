## To Do

## General
- [ ] Document DB formats & extra important info
- [ ] Standardized endpoint testing (would be difficult to implement though)

## Accounts
- [ ] Register & Sign in endpoints that allow Scratch Auth & Email
- [ ] Email should be an optional account parameter that is able to change
- [ ] Email account spam protection (email accounts must verify their email to exist and must be from @gmail.com)
- [ ] Account Format: [account-schema.md](./docs/account-schema.md)
- [ ] Accounts should be able to have their own PFP and Username (limit of 20 days inbetween PFP & Username updates)
- [ ] Proper Login & Sign-up endpoints
- [ ] Assign projects to owners via account ID
- [ ] "privateCode" should be generalized to "accountToken"
- [ ] Allow existing data to be converted to this new account system

#### Secondary priorities
- [ ] Password recovery via email (accounts not made with email would be encouraged to add one)
- [ ] Expiring tokens (login tokens should expire after a month or so)
- [ ] Custom Scratch auth API (due to problems with the existing Scratch Auth)
- [ ] 2-Factor authentication (would be optional, should be to secure email accounts, password recovery would require 2-Factor to change the password)

## Projects
- [ ] Store project assets seperately

## Moderation
- [ ] Allow project assets to be moderated
- [x] Allow reports to be reviewed by mods

## Reporting
- [x] Add reporting projects and users with reasons
- [x] Save multiple reports from same user but don't count them
- [ ] Add report to user if they report too much content too quickly
- [x] Add report to user if they report the same content more than 3 times
- [ ] Automatically add a report to projects with auto-detected content(?)

## Ranking
- [x] Rank users based on if they have more than 3 projects and signed in 5 days ago
- [x] Only ranked users should be able to use Custom Extensions, Files, iframe, HTTP, Website Requests, Network, etc.