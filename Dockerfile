FROM ubuntu:trusty

RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install python-pip python-dev git
ENV HOME /root
RUN pip install --user git+https://github.com/twisted/twisted

ADD . /root/txdockerdns
WORKDIR /root/txdockerdns
RUN python setup.py install --user
ENTRYPOINT ["/root/.local/bin/txdockerdns"]
