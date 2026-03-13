var express = require('express');
var router = express.Router();
let slugify = require('slugify')
let categoryManager = require('../schemas/categories')

/* GET categories listing. */
router.get('/', async function (req, res, next) {
  try {
    let data = categoryManager.findAll();
    res.send(data);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

router.get('/slug/:slug', async function (req, res, next) {
  try {
    let slug = req.params.slug;
    let result = categoryManager.findBySlug(slug);
    if (result) {
      res.status(200).send(result)
    } else {
      res.status(404).send({
        message: "SLUG NOT FOUND"
      })
    }
  } catch (error) {
    res.status(404).send({
      message: "SLUG NOT FOUND"
    })
  }
});

router.get('/:id', async function (req, res, next) {
  try {
    let result = categoryManager.findById(req.params.id);
    if (result) {
      res.status(200).send(result)
    } else {
      res.status(404).send({
        message: "ID NOT FOUND"
      })
    }
  } catch (error) {
    res.status(404).send({
      message: "ID NOT FOUND"
    })
  }
});

router.post('/', async function (req, res, next) {
  try {
    let newCategory = categoryManager.create(
      req.body.name,
      slugify(req.body.name, {
        replacement: '-', lower: true, locale: 'vi',
      }),
      req.body.description || '',
      req.body.images || []
    );
    res.send(newCategory);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
});

router.put('/:id', async function (req, res, next) {
  try {
    let result = categoryManager.update(req.params.id, req.body);
    if (result) {
      res.status(200).send(result)
    } else {
      res.status(404).send({
        message: "ID NOT FOUND"
      })
    }
  } catch (error) {
    res.status(404).send({
      message: "ID NOT FOUND"
    })
  }
});

router.delete('/:id', async function (req, res, next) {
  try {
    let result = categoryManager.delete(req.params.id);
    if (result) {
      res.status(200).send(result)
    } else {
      res.status(404).send({
        message: "ID NOT FOUND"
      })
    }
  } catch (error) {
    res.status(404).send({
      message: "ID NOT FOUND"
    })
  }
});

module.exports = router;
