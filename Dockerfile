FROM registry.access.redhat.com/ubi9/nodejs-20-minimal

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./

RUN npm install

# Bundle app source
COPY . .

EXPOSE 3000
CMD [ "node", "server.js" ]
