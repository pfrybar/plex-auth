FROM node:10.12.0

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
RUN mkdir /config
COPY ./config/config.json /config/

EXPOSE 3000
CMD [ "npm", "start" ]
