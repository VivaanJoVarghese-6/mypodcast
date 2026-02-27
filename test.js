const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);

const mongoose = require('mongoose');

mongoose.connect('mongodb+srv://vivaan:vivaan123@cluster0.tog5hzm.mongodb.net/myDatabase')
  .then(() => console.log('Connected!'))
  .catch(err => console.error(err));