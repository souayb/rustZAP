const express = require("express");
const app = express();

app.get("/item/:id", (req, res) => {
  const id = req.params.id;
  const extra = req.query.debug;
  res.send(id + extra);
});

app.listen(3000);
