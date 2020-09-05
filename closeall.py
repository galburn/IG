#!/usr/bin/env python
# -*- coding: ASCII
import requests
import logging
import json
import pprint


# LIVE values
hostName = "api.ig.com"
applicationKey = 'cf746c788888880d5e0339999925b78aaaab4155'           # LIVE!
userName = 'liveflea'
password = "PASSWORD_NOT_REALLY"

#Demo values - Place this below the live.  Comment out when golive happens
hostName = "demo-api.ig.com"
applicationKey = "a347395392345093945893490034abababbba893"  # Demo
userName = 'demoflea'
password = 'DEMOPASSWORD'

logging.basicConfig(filename="closeall.log",
                    level=logging.DEBUG,
                    format="%(asctime)s %(message)s")
logger = logging.getLogger()
loggedIn = False #* Global var for our login status
accountId = ""
accessToken = ""
refreshToken = ""
position_list = ""                #List of open positions


def main():
    login()
    #  now that we have the client ID, get a list of open positions
    if loggedIn:
        logging.debug("we are logged in - accountId=%s" % accountId)
        getPosList()
        if len(position_list) > 0:
            closePositions()
            getPosList()
    else:
        logger.error("Login failure, so we can't continue")

def login():
    # Login to server using REST API
    global loggedIn
    global accountId
    global accessToken
    global refreshToken
    endpoint = "gateway/deal/session"
    apiVersion = 3
    logger.debug(80 * "=")
    headers = {'Content-Type': 'application/json; charset=utf-8',
               'Accept': 'application/json; charset=utf-8',
               'X-IG-API-KEY': applicationKey,
               'Version': str(apiVersion)
               }
    data = {"identifier": userName,
            "password": password}
    url = "https://" + hostName + "/" + endpoint
    try:
        r = requests.post(url, data=json.dumps(data), headers=headers)
    except:
        logger.error("login error of some unknown type")
    else:
        status = r.status_code
        headers = r.headers
        logger.debug("headers=%s" % headers)
        logger.error("request status=%s" % status)
        loggedIn = True
        d = json.loads(r.text)
        logger.error("request follows...")
        logger.error(r)
        logger.error(d)
        logger.error("clientId=%s" % d["clientId"])
        accountId = d["accountId"]
        lightstreamerEndpoint = d["lightstreamerEndpoint"]
        logger.error("lightstreamerEndpoint=%s" % d["lightstreamerEndpoint"])
        p = "fdfdggf"
        oauthToken = d["oauthToken"]
        # logger.error("oauthToken=%s" % d["oauthToken"])
        accessToken = oauthToken["access_token"]
        refreshToken = oauthToken["refresh_token"]
    finally:
        logger.debug("End of login")


def getPosList():
    """ get list of positions """
    global accessToken
    global position_list
    endpoint = "gateway/deal/positions" # Might be just positions
    url = "https://" + hostName + "/" + endpoint
    logger.debug("accessToken=%s" % accessToken)
    logger.debug("refreshToken=%s" % refreshToken)
    global accountId
    logging.debug("now to get a pos list")
    apiVersion = 2    # 1,2,3 depending upon request
    headersAuth = {'Content-Type': 'application/json; charset=utf-8',
                   'Accept': 'application/json; charset=utf-8',
                   'X-IG-API-KEY': applicationKey,
#                  'CST': CST_token,
                   'Authorization': 'Bearer ' + accessToken,
                   'Version': str(apiVersion),
                   'IG-ACCOUNT-ID': accountId,
                   'X-SECURITY-TOKEN': accessToken}
    url = "https://" + hostName + "/" + endpoint
    r = requests.get(url, headers=headersAuth)
    logger.debug("r=%s" % r)
    #logger.debug(accountId)
    text = r.text                        # The json string
    positions = json.loads(text)
    position_list = positions["positions"]
    logger.debug("number of postions = %s" % len(position_list))
    print("There are %s open positions for this account" % len(position_list))


def closePositions():
    # Closes all positions in position_list
    # Should be able to use a DELETE instead of the POST with " '_method':'DELETE'," header.
    # look at the API companion sometime, as the JS appears to do a DELETE even though the Webpage Inspect
    # trace shows a POST.  Confusing
    global position_list
    endpoint = "gateway/deal/positions/otc"
    for position in position_list:
        logger.debug(position)
        dealId = position["position"]["dealId"]
        print("closing deal %s" % dealId)
        direction = position["position"]["direction"]
        size = position["position"]["size"]
        epic = position["market"]["epic"]
        logger.debug(">>>>>The epic is:%s" % epic)
        expiry = position["market"]["expiry"]
        if direction == "BUY":                  #Invert direction as we're closing the position
            direction = "SELL"
        else:
            direction = "BUY"
        logger.debug("dealId = %s" % dealId)
        apiVersion = 1  # 1 has fewer constraints but V2 gives a page not found.
        headersAuth = {'Content-Type': 'application/json; charset=utf-8',
                       'Accept': 'application/json; charset=utf-8',
                       'X-IG-API-KEY': applicationKey,
                       'Authorization': 'Bearer ' + accessToken,
                       'Version': str(apiVersion),
                       'IG-ACCOUNT-ID': accountId,
                       '_method':'DELETE',
                       'X-SECURITY-TOKEN': accessToken}
        url = "https://" + hostName + "/" + endpoint
        order_type = 'MARKET'
        data = {"dealId":dealId,
                "direction": direction,
                "orderType": order_type,
                "size": size}
        logger.debug("attempting to close it")
        logger.debug("request payload is:-")
        logger.debug(json.dumps(data))
        r = requests.post(url, headers=headersAuth, data=json.dumps(data))
        logger.debug(r)
        text = r.text  # The json string
        logger.debug(text)


if __name__ == '__main__':
    main()

# end of code