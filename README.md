# wfp_decoder
Decode Microsoft Windows Filtering Platform (WFP) rules.

This web-based tool decodes the wfpstate.xml produced by the command
**netsh wfp show state**
and provides a tabular view of all the providers, layers and rules.


## To deploy WFP Decoder:

Install the python dependencies specified in requirements.txt. You can use a virtual environment (venv).
Build the docker image:

    docker build -t wfpdump .
    
Run it as follows:

    docker run -p 8000:8000 wfpdump

Point your browser to http://localhost:8000/wfpdump

If you are running this on a remote system, add the ALLOWED_HOSTS argument specifying the external IP address of the remote system.

    docker run -p 8000:8000 -e ALLOWED_HOSTS="host_ip" wfpdump

