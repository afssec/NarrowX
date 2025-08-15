function isValidEndpoint(url) {
  return (
    !/\.(css|jpg|jpeg|png|gif|svg|woff|woff2|ttf|eot|ico|mp3|mp4|webm|webp|br|map)$/i.test(url) &&
    !/^(chrome|about|file|blob|data):\/\//i.test(url) &&
    (url.startsWith('http') || url.startsWith('/'))
  );
}