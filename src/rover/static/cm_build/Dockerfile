FROM node:22-alpine
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Add source file
COPY index.js ./

# Install esbuild globally for CLI usage
RUN npm install -g esbuild

# Bundle, minify, and output a self-contained IIFE script
CMD ["esbuild", "index.js", "--bundle", "--minify", "--outfile=dist/bundle.js", "--format=iife"]
