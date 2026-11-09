# Source: Trellix Advanced Research Center — "Amadey Exploiting Self-Hosted GitLab to Distribute StealC"
# URL: https://www.trellix.com/blogs/research/amadey-exploiting-self-hosted-gitlab-to-distribute-stealc/
# Published: 2025-12-18 | Collected: 2026-10-02 | TLP:CLEAR | Admiralty: A2
# Copied as published (defanged). Do not edit — normalisation happens in week-03.

## File hashes
| Type   | Value                                                            | Description                        |
| ------ | ---------------------------------------------------------------- | ---------------------------------- |
| SHA256 | d7a366fa4d31c901ce3bcb6760d7bb5aa7cab49bb54d8c6551b3df14c8cf64e7 | Amadey Loader (Yfgfwb.exe)         |
| SHA256 | b5d4cc84845cb101f8bda324729ebedd8acd36cc8ec32f80969c4fb6d3c2b8a7 | StealC Payload (x64_protect.exe)   |
| SHA256 | bae0f38f58ad93728261f09840721ebedb9669a445f40083396fdd0da38a22a7 | Amadey Clipper Plugin (clip64.dll) |

## Network indicators
| Type   | Value                                                             | Description                 |
| ------ | ----------------------------------------------------------------- | --------------------------- |
| IP     | 91[.]92[.]243[.]129                                               | Amadey C2 Server            |
| URL    | http://91[.]92[.]243[.]129/0gjSy4hf3/index.php                    | Amadey C2 Panel             |
| URL    | http://91[.]92[.]243[.]129/0gjSy4hf3/Login.php                    | Amadey C2 Check-in          |
| IP     | 158[.]94[.]208[.]130                                              | StealC C2 Server            |
| URL    | http://158[.]94[.]208[.]130/8528aa6d5ece46dc.php                  | StealC C2 Endpoint          |
| Domain | gitlab[.]bzctoons[.]net                                           | Exploited GitLab Instance   |
| URL    | https://gitlab[.]bzctoons[.]net/suau/fds/-/raw/main/protected.zip | StealC Payload Download URL |
| Domain | bzctoons[.]net                                                    | Parent Domain               |

## System artifacts
| Type           | Value                            | Description                            |
| -------------- | -------------------------------- | -------------------------------------- |
| Mutex          | f936986d553273aef6eeaeef713ad28f | Instance prevention mutex              |
| Bot ID         | 0702f                            | Hardcoded Amadey botnet identifier     |
| Decryption Key | 828065b4fbbccc7d69743a0648c2f656 | String decryption key                  |
| Directory      | %APPDATA%\f936986d553273\        | Amadey plugin storage path             |
| Directory      | %TEMP%\067640a009\               | Amadey drop directory                  |
| Directory      | %TEMP%\10000340261\protected\    | StealC extraction path                 |
| File           | Yfgfwb.exe                       | Amadey loader executable               |
| File           | clip64.dll                       | Clipper plugin (crypto wallet swapper) |
| File           | x64_protect.exe                  | StealC infostealer executable          |
| File           | protected.zip                    | Compressed StealC payload              |
| Task           | C:\Windows\Tasks\Yfgfwb.job      | Persistence scheduled task             |
