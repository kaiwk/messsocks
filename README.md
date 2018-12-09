# Messsocks
[![Build Status](https://travis-ci.org/kaiwk/messsocks.svg?branch=master)](https://travis-ci.org/kaiwk/messsocks)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=kaiwk_messsocks&metric=coverage)](https://sonarcloud.io/dashboard?id=kaiwk_messsocks)

Tested with cURL and browser proxy.

1. Setup

``` bash
sudo mkdir /var/log/messsocks
sudo chmod $USER /var/log/messsocks
  ```

2. Client & Server

``` bash
python messsocks/messclient.py
python messsocks/messserver.py
```
