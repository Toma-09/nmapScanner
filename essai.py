
    state = scan[host]['tcp'][port]['state']
    reason = scan[host]['tcp'][port]['reason']
    service = scan[host]['tcp'][port]['name']
    product = scan[host]['tcp'][port]['product']
    version = scan[host]['tcp'][port]['version']

    if state == "closed":
        print('Port : %s\t \tState : closed' % port)

    elif state == "filtered":
        print('Port : %s\t \tState : filtered' % port)

    else:
        print('Port : %s\t\tState : %s\t Reason : %s\t Service : %s\t\t\t Product : %s\t\t\t Version : '
              '%s' % (port, state, reason, service, product, version))
        result['port'] = port
        result['state'] = state
        result['reason'] = reason
        result['service'] = service
        result['product'] = product
        result['version'] = version

    print(resultat)
    resultatbiss.append(result)
    resultat["ports"] = resultatbiss
