# eiqlib
a python3 library for interacting with EclecticIQ

## eiqjson
a simple python3 library for generating EIQ API json bodies.
only compatible with EclecticIQ 2.2

### dependencies
- python3
- standard python3 libraries (json, time, uuid, urllib.request)
- EclecticIQ 2.2 (as server for the API to communicate with)

### example usage of eiqjson.EIQEntity

```python
from eiqlib.eiqjson import EIQEntity
indicator = EIQEntity()

# General entity settings
indicator.set_entity(indicator.ENTITY_INDICATOR)
indicator.set_entity_title('[tag1] [tag2] <domain> - <iso-8601 timestamp>')
indicator.set_entity_description('<from email-address>\n<email subject>\n<notes about sighting type>')
indicator.set_entity_observed_time('YYYY-MM-DDTHH:MM:SSZ')
indicator.set_entity_confidence('Unknown')
indicator.set_entity_tlp('AMBER')
indicator.set_entity_source('<uuid of ingestion source>')

# Indicator-specific required fields
indicator.set_entity_impact('Unknown')
indicator.add_indicator_type(indicator.INDICATOR_C2)
indicator.add_indicator_type(indicator.INDICATOR_HOST_CHARACTERISTICS)

# Adding observables
indicator.add_observable(indicator.OBSERVABLE_IPV4, '127.0.0.1')
indicator.add_observable(indicator.OBSERVABLE_DOMAIN, 'www.example.org')
indicator.add_observable(indicator.OBSERVABLE_URI, 'https://www.example.org/test.php')
indicator.add_observable(indicator.OBSERVABLE_EMAIL, 'postmaster@example.org')

with open('EntityTitle.json', 'w') as f:
  f.write(indicator.get_as_json())
```

### example usage of eiqjson.EIQRelation

```python
from eiqlib.eiqjson import EIQEntity, EIQRelation
rel = EIQRelation()
rel.set_relation(rel.RELATION_STIX_UPDATE)
rel.set_source('<uuid of updated entity>', EIQEntity.ENTITY_SIGHTING)
rel.set_target('<uuid of superseded entity>', EIQEntity.ENTITY_SIGHTING)
rel.set_ingest_source('<uuid of ingestion source>')

with open('UpdateCall.json', 'w') as f:
  f.write(rel.get_as_json())
```

## eiqcalls
python3 bindings to the EclecticIQ REST api

### dependencies
- python3
- standard python3 libraries (json, urllib.request)

### example usage

```python
from eiqlib.eiqcalls import EIQApi
api = EIQApi()
api.set_host('https://eiq.lan/private')
api.set_credentials('<username>', '<password>')

# entity_json can be generated with the help of eiqjson.EIQEntity
response = api.create_entity(entity_json)
if not response or 'errors' in response:
  if response:
    for err in response['errors']:
      print('[error %d] %s' % (err['status'], err['title']))
      print('\t%s' % (err['detail'],))
  else:
    print('unable to get a response from host')
```

### example of auto-updating previous entities
```python
from eiqlib.eiqcalls import EIQApi
api = EIQApi()
api.set_host('https://eiq.lan/private')
api.set_credentials('<username>', '<password>')
# [optional] generating a token this way allows you to pass it manually to all other
# calls of EIQApi. If you do not pass a token to EIQApi methods, it does a do_auth
# call internally.
token = api.do_auth()

# entity_json can be generated with the help of eiqjson.EIQEntity
# if you use create_entity this way, every subsequently created entity using the same update_identifier
# will update the latest version already in EIQ
response = api.create_entity(entity_json, token=token, update_identifier="Event-000")
```
