#
# Copyright (C) 2023 ColorTokens Inc.
# By Venky Raju <venky.raju@colortokens.com>
#

from django.shortcuts import render
from django.conf import settings
from django.http import HttpResponse
import os
from . import wfpstate

def main(request):
   return _handle_main_request(request)

def _handle_main_request(request, msg=None):
   return render(request, "wfpdump/main.html", {'msg': msg})

def demo(request):
   demo_filename = os.path.join(settings.BASE_DIR, 
                  'wfpdump', 'demo', 'wfpstate.xml')
   try:
      with open(demo_filename) as demo_file:
         wfpdata = demo_file.read()
   except Exception as e:
      return render(request, 'wfpdump/main.html', {'msg': e})

   return _handle_decode_request(request, wfpdata, 'Demo file')
      
def upload(request):

   if request.method != 'POST':
      return _handle_main_request(request)

   if request.method == 'POST' and 'dumpfile' in request.FILES:
         dump_file = request.FILES['dumpfile']
         wfpdata = dump_file.read().decode()
         filename = dump_file.name
         return _handle_decode_request(request, wfpdata, filename)
   else:
      return _handle_main_request(request, 'Please choose a file!')

def _handle_decode_request(request, wfpdata, filename):

   state = None

   try:
      state = wfpstate.WfpState()
      state.parse(wfpdata)
   except Exception as e:
      context = {
         'msg': 'Unable to parse this file. If this is a valid WFP state file please report this bug. '+
                  'Exception: '+str(e)
      }
      return render(request, 'wfpdump/main.html', context)

   context = {
               'filename': filename,
               'datetime': state.datetime,
               'providers': state.providers,
               'sublayers': state.sublayers,
               'layers': state.layers,
               'filters_by_provider': state.filters_by_provider,
               'filters_by_sublayer': state.filters_by_sublayer,
               'filters_by_layer': state.filters_by_layer
            }
   request.session['session.context'] = context
   return render(request, 'wfpdump/result.html', context)

def show_provider(request, key):

   if 'session.context' in request.session:
      session_context = request.session['session.context']
      filters = session_context['filters_by_provider'][key]

      context = {
                  'name': session_context['providers'][key]['name'],
                  'desc': session_context['providers'][key]['desc'],
                  'layers': session_context['layers'],
                  'sublayers': session_context['sublayers'],
                  'filter_count': session_context['providers'][key]['filter_count'],
                  'filters': filters
               }

      return render(request, 'wfpdump/provider.html', context)

   else:
      return HttpResponse('Could not find session data')

def show_layer(request, key):

   if 'session.context' in request.session:
      session_context = request.session['session.context']
      filters = session_context['filters_by_layer'][key]

      context = {
                  'name': session_context['layers'][key]['name'],
                  'sublayers': session_context['sublayers'],
                  'providers': session_context['providers'],
                  'filter_count': session_context['layers'][key]['filter_count'],
                  'filters': filters
               }

      return render(request, 'wfpdump/layer.html', context)

   else:
      return HttpResponse('Could not find session data')
   
def show_sublayer(request, key):

   if 'session.context' in request.session:
      session_context = request.session['session.context']
      filters = session_context['filters_by_sublayer'][key]

      context = {
                  'name': session_context['sublayers'][key]['name'],
                  'providers': session_context['providers'],
                  'layers': session_context['layers'],
                  'filter_count': session_context['sublayers'][key]['filter_count'],
                  'filters': filters
               }

      return render(request, 'wfpdump/sublayer.html', context)

   else:
      return HttpResponse('Could not find session data')