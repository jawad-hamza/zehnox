FROM node:24-alpine

WORKDIR /app

COPY . .

RUN node build.js

ENV NODE_ENV=production
ENV TRUST_PROXY=1

EXPOSE 3000

CMD ["./docker-entrypoint.sh"]
