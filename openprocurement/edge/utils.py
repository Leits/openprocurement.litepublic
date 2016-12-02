# -*- coding: utf-8 -*-
import os
from datetime import datetime
from pytz import timezone
from cornice.resource import resource, view
from cornice.util import json_error
from functools import partial
from openprocurement.edge.traversal import tender_factory, auction_factory, contract_factory, plan_factory
from pyramid.exceptions import URLDecodeError
from pyramid.compat import decode_path_info
from munch import munchify
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from logging import getLogger
from pkg_resources import get_distribution
from json import dumps

PKG = get_distribution(__package__)
LOGGER = getLogger(PKG.project_name)

SERVICE_FIELDS = ('__parent__', '_rev', '_id', 'doc_type')

TZ = timezone(os.environ['TZ'] if 'TZ' in os.environ else 'Europe/Kiev')

json_view = partial(view, renderer='json')

def get_now():
    return datetime.now(TZ)


def add_logging_context(event):
    request = event.request
    params = {
        'API_VERSION': request.registry.api_version,
        'TAGS': 'python,api',
        'USER': str(request.authenticated_userid or ''),
        'CURRENT_URL': request.url,
        'CURRENT_PATH': request.path_info,
        'REMOTE_ADDR': request.remote_addr or '',
        'USER_AGENT': request.user_agent or '',
        'REQUEST_METHOD': request.method,
        'TIMESTAMP': get_now().isoformat(),
        'REQUEST_ID': request.environ.get('REQUEST_ID', ''),
        'CLIENT_REQUEST_ID': request.headers.get('X-Client-Request-ID', ''),
    }

    request.logging_context = params


def update_logging_context(request, params):
    if not request.__dict__.get('logging_context'):
        request.logging_context = {}

    for x, j in params.items():
        request.logging_context[x.upper()] = j


def set_logging_context(event):
    request = event.request

    params = {}
    if request.params:
        params['PARAMS'] = str(dict(request.params))
    if request.matchdict:
        for x, j in request.matchdict.items():
            params[x.upper()] = j
    if 'tender' in request.validated:
        params['TENDER_REV'] = request.validated['tender']._rev
        params['TENDERID'] = request.validated['tender'].tenderID
        params['TENDER_STATUS'] = request.validated['tender'].status
    update_logging_context(request, params)


def context_unpack(request, msg, params=None):
    if params:
        update_logging_context(request, params)
    logging_context = request.logging_context
    journal_context = msg
    for key, value in logging_context.items():
        journal_context["JOURNAL_" + key] = value
    return journal_context


def error_handler(errors, request_params=True):
    params = {
        'ERROR_STATUS': errors.status
    }
    if request_params:
        if errors.request.params:
            params['PARAMS'] = str(dict(errors.request.params))
    if errors.request.matchdict:
        for x, j in errors.request.matchdict.items():
            params[x.upper()] = j
    if 'tender' in errors.request.validated:
        params['TENDER_REV'] = errors.request.validated['tender']._rev
        params['TENDERID'] = errors.request.validated['tender'].tenderID
        params['TENDER_STATUS'] = errors.request.validated['tender'].status
    LOGGER.info('Error on processing request "{}"'.format(dumps(errors, indent=4)),
                extra=context_unpack(errors.request, {'MESSAGE_ID': 'error_handler'}, params))
    return json_error(errors)

opresource = partial(resource, error_handler=error_handler, factory=tender_factory)
eaopresource = partial(resource, error_handler=error_handler, factory=auction_factory)
contractingresource = partial(resource, error_handler=error_handler, factory=contract_factory)
planningresource = partial(resource, error_handler=error_handler, factory=plan_factory)


class EDGEResource(object):

    def __init__(self, request, context):
        self.context = context
        self.request = request
        self.db = request.registry.db
        self.server_id = request.registry.server_id
        self.LOGGER = getLogger(type(self).__module__)


def encrypt(uuid, name, key):
    iv = "{:^{}.{}}".format(name, AES.block_size, AES.block_size)
    text = "{:^{}}".format(key, AES.block_size)
    return hexlify(AES.new(uuid, AES.MODE_CBC, iv).encrypt(text))


def decrypt(uuid, name, key):
    iv = "{:^{}.{}}".format(name, AES.block_size, AES.block_size)
    try:
        text = AES.new(uuid, AES.MODE_CBC, iv).decrypt(unhexlify(key)).strip()
    except:
        text = ''
    return text


def extract_doc_adapter(request, doc_id, doc_type):
    db = request.registry.db
    doc = db.get(doc_id)
    if doc is None or doc.get('doc_type') != doc_type:
        request.errors.add('url', '{}_id'.format(doc_type.lower()), 'Not Found')
        request.errors.status = 404
        raise error_handler(request.errors)
    return munchify(doc)


def extract_doc(request, doc_type):
    try:
        # empty if mounted under a path in mod_wsgi, for example
        path = decode_path_info(request.environ['PATH_INFO'] or '/')
    except KeyError:
        path = '/'
    except UnicodeDecodeError as e:
        raise URLDecodeError(e.encoding, e.object, e.start, e.end, e.reason)

    doc_id = ""
    # extract doc id
    parts = path.split('/')
    if len(parts) < 4 or parts[3] != '{}s'.format(doc_type.lower()):
        return

    doc_id = parts[4]
    return extract_doc_adapter(request, doc_id, doc_type)


def extract_tender(request):
    return extract_doc(request, 'Tender')


def extract_auction(request):
    return extract_doc(request, 'Auction')


def extract_contract(request):
    return extract_doc(request, 'Contract')


def extract_plan(request):
    return extract_doc(request, 'Plan')

def clean_up_doc(doc, service_fields=SERVICE_FIELDS):
    for field in service_fields:
        if field in doc:
            del doc[field]
    return doc
