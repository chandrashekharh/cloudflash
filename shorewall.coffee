@include = ->
    fs = require 'fs'
    validate = require('json-schema').validate
    exec = require('child_process').exec
    path = require 'path'    
    
    db = 
       main: require('dirty') '/tmp/shorewall.db'
       client: require('dirty') '/tmp/shorewallclient.db'
    
    cloudflash = require './cloudflash', { include: @include }
    
    
    #Test schema to validate incoming JSON
    schema =
        name: "shorewall"
        type: "object"
        additionalProperties: false
        properties:
                'STARTUP_ENABLED':   { type: "string", required: true }
                'VERBOSITY':         { type: "string", required: true }
                'LOGFILE':           { type: "string", required: true }
                'STARTUP_LOG':       { type: "string", required: true }
                'LOG_VERBOSITY':     { type: "string", required: true }
                'LOGFORMAT':         { type: "string", required: true }
                'LOGTAGONLY':        { type: "string", required: true }
                'LOGRATE':           { type: "string", required: true } 
                'LOGBURST':          { type: "string", required: true }
                'LOGALLNEW':           { type: "string", required: true }
                'BLACKLIST_LOGLEVEL':  { type: "string", required: true }
                'MACLIST_LOG_LEVEL':   { type: "string", required: true }
                'TCP_FLAGS_LOG_LEVEL': { type: "string", required: true }
                'SMURF_LOG_LEVEL':     { type: "string", required: true }
                'LOG_MARTIANS':        { type: "string", required: true }
                'IPTABLES':            { type: "string", required: true }
                'IP':                  { type: "string", required: true }
                'TC':                  { type: "string", required: true }
                'IPSET':               { type: "string", required: true }
                'PERL':                { type: "string", required: true }
                'PATH':                { type: "string", required: true }
                'SHOREWALL_SHELL':     { type: "string", required: true }
                'SUBSYSLOCK':          { type: "string", required: true }
                'MODULESDIR':          { type: "string", required: true }
                'CONFIG_PATH':         { type: "string", required: true }
                'RESTOREFILE':         { type: "string", required: true }
                'IPSECFILE':           { type: "string", required: true }
                'LOCKFILE':            { type: "string", required: true }
                'DROP_DEFAULT':        { type: "string", required: true }
                'REJECT_DEFAULT':      { type: "string", required: true }
                'ACCEPT_DEFAULT':      { type: "string", required: true }
                'QUEUE_DEFAULT':       { type: "string", required: true }
                'NFQUEUE_DEFAULT':     { type: "string", required: true }
                'RSH_COMMAND':         { type: "string", required: true }
                'RCP_COMMAND':         { type: "string", required: true}
                'IP_FORWARDING':       { type: "string", required: true }
                'ADD_IP_ALIASES':      { type: "string", required: true }
                'ADD_SNAT_ALIASES':    { type: "string", required: true }
                'RETAIN_ALIASES':      { type: "string", required: true }
                'TC_ENABLED':          { type: "string", required: true }
                'TC_EXPERT':           { type: "string", required: true }
                'TC_PRIOMAP':          { type: "string", required: true }
                'CLEAR_TC':            { type: "string", required: true }
                'MARK_IN_FORWARD_CHAIN': { type: "string", required: true }
                'CLAMPMSS':              { type: "string", required: true }
                'ROUTE_FILTER':          { type: "string", required: true }
                'DETECT_DNAT_IPADDRS':   { type: "string", required: true }
                'MUTEX_TIMEOUT':         { type: "string", required: true }
                'ADMINISABSENTMINDED':   { type: "string", required: true }
                'BLACKLISTNEWONLY':      { type: "string", required: true }
                'DELAYBLACKLISTLOAD':    { type: "string", required: true }
                'MODULE_SUFFIX':         { type: "string", required: true }
                'DISABLE_IPV6':          { type: "string", required: true }
                'BRIDGING':              { type: "string", required: true }
                'DYNAMIC_ZONES':         { type: "string", required: true }
                'PKTTYPE':               { type: "string", required: true }
                'NULL_ROUTE_RFC1918':    { type: "string", required: true }
                'MACLIST_TABLE':         { type: "string", required: true }
                'MACLIST_TTL':           { type: "string", required: true }
                'SAVE_IPSETS':           { type: "string", required: true }
                'MAPOLDACTIONS':         { type: "string", required: true }
                'FASTACCEPT':            { type: "string", required: true }
                'IMPLICIT_CONTINUE':     { type: "string", required: true }
                'HIGH_ROUTE_MARKS':      { type: "string", required: true }
                'USE_ACTIONS':           { type: "string", required: true }
                'OPTIMIZE':              { type: "string", required: true }
                'EXPORTPARAMS':          { type: "string", required: true }
                'EXPAND_POLICIES':       { type: "string", required: true }
                'KEEP_RT_TABLES':        { type: "string", required: true } 
                'DELETE_THEN_ADD':       { type: "string", required: true }
                'MULTICAST':             { type: "string", required: true }
                'DONT_LOAD':             { type: "string", required: true }
                'AUTO_COMMENT':          { type: "string", required: true }
                'MANGLE_ENABLED':        { type: "string", required: true }
                'USE_DEFAULT_RT':        { type: "string", required: true }
                'RESTORE_DEFAULT_ROUTE':  { type: "string", required: true }
                'AUTOMAKE':               { type: "string", required: true }
                'WIDE_TC_MARKS':         { type: "string", required: true }
                'TRACK_PROVIDERS':        { type: "string", required: true }
                'ZONE2ZONE':              { type: "string", required: true }
                'ACCOUNTING':             { type: "string", required: true }
                'DYNAMIC_BLACKLIST':      { type: "string", required: true }
                'OPTIMIZE_ACCOUNTING':    { type: "string"  }
                'LOAD_HELPERS_ONLY':      { type: "string"  }
                'REQUIRE_INTERFACE':      { type: "string"  }
                'FORWARD_CLEAR_MARK':     { type: "string"  }
                'BLACKLIST_DISPOSITION':  { type: "string"  }
                'MACLIST_DISPOSITION':    { type: "string"  }
                'TCP_FLAGS_DISPOSITION':  { type: "string"  } 

    #Test schema to validate incoming JSON
    schemaZones =
        name: "shorewallzones"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                fw:
                    items: {type: "string"}
                net:
                    items: {"type":"string"}
                loc:
                    items: {"type":"string"}
                dmz:
                    items: {"type":"string"}


    #Test schema to validate incoming JSON
    schemaPolicy =
        name: "shorewallpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                "$FW": 
                    items: {"type":"string"}
                net:
                    items: {"type":"string"}
                loc:
                    items: {"type":"string"}
                dmz:
                    items: {"type":"string"}
                all:
                    items: {"type":"string"}             

    schemainterfaces =
        name: "shorewallinterfaces"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                net:
                    items: {"type":"string"}
                loc:
                    items: {"type":"string"}
                dmz:
                    items: {"type":"string"}

    schemanet =
        name: "shorewallnet"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ZONE':          { type: "string", required: true }
                'INTERFACE':     { type: "string", required: true }
                'BROADCAST':       { type: "string", required: true }
                'OPTIONS':           { type: "string", required: true }

    schemaloc =
        name: "shorewallloc"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ZONE':          { type: "string", required: true }
                'INTERFACE':     { type: "string", required: true }
                'BROADCAST':       { type: "string", required: true }
                'OPTIONS':           { type: "string", required: true }

    schemadmz =
        name: "shorewalldmz"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ZONE':          { type: "string", required: true }
                'INTERFACE':     { type: "string", required: true }
                'BROADCAST':       { type: "string", required: true }
                'OPTIONS':           { type: "string", required: true }

    schemarules =
        name: "shorewallrules"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                "FTP(DROP)":
                    items: {"type":"string"}
                ACCEPT:
                    items: {"type":"string"}

    schemaaccept =
        name: "shorewallaccept"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true } 
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true } 
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }
                    

    schemadrop =
        name: "shorewalldrop"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }


    schemareject =
        name: "shorewallreject"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }

    schemadnat =
        name: "shorewalldnat"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }

    schemaredirect =
        name: "shorewallredirect"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }


    schemaqueue =
        name: "shorewallqueue"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }

    schemanfqueue =
        name: "shorewallnfqueue"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }

    schemanonat =
        name: "shorewallnonat"
        type: "object"
        additionalProperties: false
        properties:
                commonname : {"type":"string", "required":true}
                'ACTION':          { type: "string", required: true }
                'SOURCE_zone':     { type: "string", required: true }
                'DEST_zone':       { type: "string", required: true }
                'PROTO':           { type: "string", required: true }
                'DEST_PORT':       { type: "string", required: true }
                'SOURCE_PORT':     { type: "string", required: true }
                'Original_DEST':   { type: "string", required: true }
                'RATE_LIMIT':      { type: "string", required: true }
                'User_Group':      { type: "string", required: true }
                'MARK':            { type: "string", required: true }
                'CONNLIMIT':       { type: "string", required: true }
                'TIME':            { type: "string", required: true }
                'HEADERS':         { type: "string", required: true }
                'SWITCH':          { type: "string", required: true }

    schemafwzones =
        name: "shorewallfwzones"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'ZONES':      { type: "string", required: true }
                'TYPE':       { type: "string", required: true }
                'OPTIONS':    { type: "string", required: true }
                'IN-OPTIONS': { type: "string", required: true }
                'OUT-OPTIONS':{ type: "string", required: true }

    schemaloczones =
        name: "shorewallloczones"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'ZONES':      { type: "string", required: true }
                'TYPE':       { type: "string", required: true }
                'OPTIONS':    { type: "string", required: true }
                'IN-OPTIONS': { type: "string", required: true }
                'OUT-OPTIONS':{ type: "string", required: true }

    schemanetzones =
        name: "shorewallnetzones"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'ZONES':      { type: "string", required: true }
                'TYPE':       { type: "string", required: true }
                'OPTIONS':    { type: "string", required: true }
                'IN-OPTIONS': { type: "string", required: true }
                'OUT-OPTIONS':{ type: "string", required: true }

    schemadmzzones =
        name: "shorewalldmzzones"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'ZONES':      { type: "string", required: true }
                'TYPE':       { type: "string", required: true }
                'OPTIONS':    { type: "string", required: true }
                'IN-OPTIONS': { type: "string", required: true }
                'OUT-OPTIONS':{ type: "string", required: true }

    schemafwpolicy =
        name: "shorewallfwpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'SRC_ZONES':  { type: "string", required: true }
                'DEST_ZONE':  { type: "string", required: true }
                'POLICY':     { type: "string", required: true }
                'LOG_LEVEL':  { type: "string", required: true }
                'LIMIT_BURST':{ type: "string", required: true }

    schemanetpolicy =
        name: "shorewallnetpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'SRC_ZONES':  { type: "string", required: true }
                'DEST_ZONE':  { type: "string", required: true }
                'POLICY':     { type: "string", required: true }
                'LOG_LEVEL':  { type: "string", required: true }
                'LIMIT_BURST':{ type: "string", required: true }

    schemalocpolicy =
        name: "shorewalllocpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'SRC_ZONES':  { type: "string", required: true }
                'DEST_ZONE':  { type: "string", required: true }
                'POLICY':     { type: "string", required: true }
                'LOG_LEVEL':  { type: "string", required: true }
                'LIMIT_BURST':{ type: "string", required: true }

    schemadmzpolicy =
        name: "shorewalldmzpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'SRC_ZONES':  { type: "string", required: true }
                'DEST_ZONE':  { type: "string", required: true }
                'POLICY':     { type: "string", required: true }
                'LOG_LEVEL':  { type: "string", required: true }
                'LIMIT_BURST':{ type: "string", required: true }

    schemaallpolicy =
        name: "shorewallallpolicy"
        type: "object"
        additionalProperties: false
        properties:
                commonname :  {"type":"string", "required":true}
                'SRC_ZONES':  { type: "string", required: true }
                'DEST_ZONE':  { type: "string", required: true }
                'POLICY':     { type: "string", required: true }
                'LOG_LEVEL':  { type: "string", required: true }
                'LIMIT_BURST':{ type: "string", required: true }



  # helper routine to validate shorewall with schema
    validateShorewall = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall JSON'
        result = validate @body, schema
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

   # helper routine to validate shorewall zones with schema
    validateShorewallZones = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall zones JSON'
        result = validate @body, schemaZones
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    # helper routine to validate shorewall policy with schema
    validateShorewallPolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall policy JSON'
        result = validate @body, schemaPolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallinterfaces = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall interfaces JSON'
        result = validate @body, schemainterfaces
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallnet = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall interfaces net JSON'
        result = validate @body, schemanet
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallloc = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall interfaces loc JSON'
        result = validate @body, schemaloc
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalldmz = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall interfaces dmz JSON'
        result = validate @body, schemadmz
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallrules = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall rules JSON'
        result = validate @body, schemarules
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallaccept = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall accept rules JSON'
        result = validate @body, schemaaccept
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalldrop = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall drop rules JSON'
        result = validate @body, schemadrop
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallreject = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemareject
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalldnat = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemadnat
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallredirect = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemaredirect
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallqueue = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemaqueue
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallnfqueue = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemanfqueue
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallnonat = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemanonat
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallfwzones = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemafwzones
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallloczones = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemaloczones
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallnetzones = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemanetzones
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalldmzzones = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemadmzzones
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalldmzpolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemadmzpolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallfwpolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemafwpolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallnetpolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemanetpolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewalllocpolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemalocpolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()

    validateShorewallallpolicy = ->
        console.log @body
        console.log 'performing schema validation on incoming shorewall reject rules JSON'
        result = validate @body, schemaallpolicy
        console.log result
        return @next new Error "Invalid service posting!: #{result.errors}" unless result.valid
        @next()


    loadService = ->
        result = cloudflash.lookup @params.id
        unless result instanceof Error
            @request.service = result
            @next()
        else
            return @next result  

    @post '/services/:id/shorewall', loadService, validateShorewall, ->
        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        for i in val
                            config += "#{key}=#{i}\n" if key is "route"
                            config += "#{key}=\"#{i}\"\n" if key is "push"
                when "number", "string"
                    config += key + '=' + val + "\n"
                

        filename = '/config/shorewall/shorewall.conf'
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.writeFileSync filename, config
            else
                fs.writeFileSync filename, config

            exec "touch /config/#{service.description.name}/on"

            db.main.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }

        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/zones', loadService, validateShorewallZones, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{key}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "fw"                             
                               tmp += "#{i}\t" if key is "net"                             
                               tmp += "#{i}\t" if key is "loc"
                               tmp += "#{i}\t" if key is "dmz"
                        config += tmp + "\n"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += key + '\t' + val + "\n"
        console.log "zones config: " + config

        filename = "/config/shorewall/#{@body.commonname}/zones"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.writeFileSync filename, config
            else
                fs.writeFileSync filename, config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/policy', loadService, validateShorewallPolicy, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{key}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "net"                             
                               tmp += "#{i}\t" if key is "loc"
                               tmp += "#{i}\t" if key is "dmz"
                               tmp += "#{i}\t" if key is "$FW"
                               tmp += "#{i}\t" if key is "all"
                        config += tmp + "\n"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += key + '\t' + val + "\n"
        console.log "zones config: " + config

        filename = "/config/shorewall/#{@body.commonname}/policy"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.writeFileSync filename, config
            else
                fs.writeFileSync filename, config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/interfaces', loadService, validateShorewallinterfaces, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{key}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "net"                             
                               tmp += "#{i}\t" if key is "loc"
                               tmp += "#{i}\t" if key is "dmz"
                               tmp += "#{i}\t" if key is "fw"
                               tmp += "#{i}\t" if key is "all"
                        config += tmp + "\n"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += key + '\t' + val + "\n"
        console.log "interfaces config: " + config

        filename = "/config/shorewall/#{@body.commonname}/interfaces"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.writeFileSync filename, config
            else
                fs.writeFileSync filename, config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules', loadService, validateShorewallrules, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{key}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "FTP(DROP)"                             
                               tmp += "#{i}\t" if key is "ACCEPT"
                               tmp += "#{i}\t" if key is "DROP"
                               tmp += "#{i}\t" if key is "REJECT"
                        config += tmp + "\n"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += key + '\t' + val + "\n"
        console.log "rules config: " + config

        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.writeFileSync filename, config
            else
                fs.writeFileSync filename, config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/accept', loadService, validateShorewallaccept, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "ACCEPT"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else

                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/drop', loadService, validateShorewalldrop, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "DROP"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/reject', loadService, validateShorewallreject, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "REJECT"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/redirect', loadService, validateShorewallredirect, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "REDIRECT"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/dnat', loadService, validateShorewalldnat, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "DNAT"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/queue', loadService, validateShorewallqueue, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "QUEUE"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"



    @post '/services/:id/shorewall/rules/nfqueue', loadService, validateShorewallnfqueue, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "NFQUEUE"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/rules/nonat', loadService, validateShorewallnonat, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "NONAT"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/rules"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/interfaces/net', loadService, validateShorewallnet, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "NET"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/interfaces"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/interfaces/loc', loadService, validateShorewallloc, ->  

        service = @request.service
        config = ''
        for key, val of @body
            switch (typeof val)
                when "object"
                    if val instanceof Array
                        tmp = "#{val}\t"                       
                        for i in val                            
                               tmp += "#{i}\t" if key is "LOC"
                        config += tmp + "\t"                                                        
                when "number", "string" 
                    if key isnt 'commonname'
                        config += val + "\t"
        console.log "rules config: " + config
        config += "\n"
        filename = "/config/shorewall/#{@body.commonname}/interfaces"
        try
            console.log "write shorewall config to #{filename}..."
            dir = path.dirname filename
            unless path.existsSync dir
                exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                    unless error
                        fs.createWriteStream(filename, flags: "a").write config
            else
                fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

            db.client.set @params.id, @body, =>
                console.log "#{@params.id} added to shorewall service configuration"
                console.log @body
                @send { result: true }
        catch err
            @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/interfaces/dmz', loadService, validateShorewalldmz, ->  

            service = @request.service
            config = ''
            for key, val of @body
                switch (typeof val)
                    when "object"
                        if val instanceof Array
                            tmp = "#{key}\t"                       
                            for i in val                            
                                   tmp += "#{i}\t" if key is "ZONE"
                                   tmp += "#{i}\t" if key is "INTERFACE"
                                   tmp += "#{i}\t" if key is "BROADCAST"
                                   tmp += "#{i}\t" if key is "OPTIONS"
                            config += key + "\t"                                                        
                    when "number", "string" 
                        if key isnt 'commonname'
                            config += val + "\t"
            console.log "rules config: " + config
            config += "\n"
            filename = "/config/shorewall/#{@body.commonname}/interfaces"
            try
                console.log "write shorewall config to #{filename}..."
                dir = path.dirname filename
                unless path.existsSync dir
                    exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                        unless error
                            fs.createWriteStream(filename, flags: "a").write config
                else
                    fs.createWriteStream(filename, flags: "a").write config

            #exec "service shorewall restart"

                db.client.set @params.id, @body, =>
                    console.log "#{@params.id} added to shorewall service configuration"
                    console.log @body
                    @send { result: true }
            catch err
                @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/zones/fwzones', loadService, validateShorewallfwzones, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/zones"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/zones/loczones', loadService, validateShorewallloczones, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/zones"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/zones/netzones', loadService, validateShorewallnetzones, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/zones"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/zones/dmzzones', loadService, validateShorewalldmzzones, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/zones"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/policy/fwpolicy', loadService, validateShorewallfwpolicy, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/policy"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"

    @post '/services/:id/shorewall/policy/netpolicy', loadService, validateShorewallnetpolicy, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/policy"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/policy/locpolicy', loadService, validateShorewalllocpolicy, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/policy"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/policy/dmzpolicy', loadService, validateShorewalldmzpolicy, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/policy"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"


    @post '/services/:id/shorewall/policy/allpolicy', loadService, validateShorewallallpolicy, ->  

          service = @request.service
          config = ''
          for key, val of @body
              switch (typeof val)
                  when "number", "string" 
                      if key isnt 'commonname'
                          config += val + "\t"
          console.log "fwzones config: " + config
          config += "\n"
          filename = "/config/shorewall/#{@body.commonname}/policy"
          try
              console.log "write shorewall config to #{filename}..."
              dir = path.dirname filename
              unless path.existsSync dir
                  exec "mkdir -p #{dir}", (error, stdout, stderr) =>
                      unless error
                          fs.createWriteStream(filename, flags: "a").write config
              else
                  fs.createWriteStream(filename, flags: "a").write config
  
              #exec "service shorewall restart"
  
              db.client.set @params.id, @body, =>
                  console.log "#{@params.id} added to shorewall service configuration"
                  console.log @body
                  @send { result: true }
          catch err
              @next new Error "Unable to write shorewall configuration into #{filename}!"
