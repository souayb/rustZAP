# Clean, runnable image for the lab (the *.insecure files under insecure/ are
# SAST fixtures, never built). Build context is this directory.
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
# The runtime .env is generated from the committed sample (kept out of git).
RUN cp dotenv.sample .env
EXPOSE 3000
CMD ["node", "server.js"]
