var express = require('express');
var router = express.Router();
let slugify = require('slugify')
let productManager = require('../schemas/products')
let categoryManager = require('../schemas/categories')

/* GET products listing. */
router.get('/', async function (req, res, next) {
  try {
    let titleQ = req.query.title ? req.query.title : '';
    let maxPrice = req.query.maxPrice ? req.query.maxPrice : 1E4;
    let minPrice = req.query.minPrice ? req.query.minPrice : 0;

    let data = productManager.findAll();
    let result = data.filter(function (e) {
      let category = categoryManager.findById(e.category);
      return (!e.isDeleted) &&
        e.title.toLowerCase().includes(titleQ.toLowerCase())
        && e.price > minPrice
        && e.price < maxPrice
    })

    // Populate category data
    result = result.map(product => ({
      ...product,
      category: categoryManager.findById(product.category)
    }));

    res.send(result);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

router.get('/slug/:slug', async function (req, res, next) {
  try {
    let slug = req.params.slug;
    let result = productManager.findBySlug(slug);
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
    let result = productManager.findById(req.params.id);
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
    let newProduct = productManager.create(
      req.body.title,
      slugify(req.body.title, {
        replacement: '-', lower: true, locale: 'vi',
      }),
      req.body.price,
      req.body.description || '',
      req.body.categoryId,
      req.body.images || []
    );
    res.send(newProduct);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
});

router.put('/:id', async function (req, res, next) {
  try {
    let result = productManager.update(req.params.id, req.body);
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
    let result = productManager.delete(req.params.id);
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

