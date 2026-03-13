const fs = require('fs');
const path = require('path');

// Đường dẫn thư mục lưu dữ liệu
const dataDir = path.join(__dirname, '../data');

// Tạo thư mục data nếu chưa tồn tại
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Hàm tạo ID tự động
const generateId = () => {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
};

// Hàm lấy tất cả dữ liệu từ file
const readDataFromFile = (filename) => {
    const filePath = path.join(dataDir, filename);
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            return JSON.parse(data);
        }
        return [];
    } catch (error) {
        console.error(`Error reading ${filename}:`, error);
        return [];
    }
};

// Hàm lưu dữ liệu vào file
const writeDataToFile = (filename, data) => {
    const filePath = path.join(dataDir, filename);
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
        return true;
    } catch (error) {
        console.error(`Error writing ${filename}:`, error);
        return false;
    }
};

// Quản lý Roles
const RoleManager = {
    filename: 'roles.json',

    findAll: function () {
        return readDataFromFile(this.filename).filter(r => !r.isDeleted);
    },

    findById: function (id) {
        const items = readDataFromFile(this.filename);
        return items.find(r => r._id === id && !r.isDeleted);
    },

    findByName: function (name) {
        const items = readDataFromFile(this.filename);
        return items.find(r => r.name === name && !r.isDeleted);
    },

    create: function (name, description = '') {
        const items = readDataFromFile(this.filename);
        const newRole = {
            _id: generateId(),
            name: name,
            description: description,
            isDeleted: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        items.push(newRole);
        writeDataToFile(this.filename, items);
        return newRole;
    },

    update: function (id, updates) {
        const items = readDataFromFile(this.filename);
        const index = items.findIndex(r => r._id === id);
        if (index !== -1) {
            items[index] = { ...items[index], ...updates, updatedAt: new Date().toISOString() };
            writeDataToFile(this.filename, items);
            return items[index];
        }
        return null;
    },

    delete: function (id) {
        return this.update(id, { isDeleted: true });
    }
};

// Quản lý Categories
const CategoryManager = {
    filename: 'categories.json',

    findAll: function () {
        return readDataFromFile(this.filename).filter(c => !c.isDeleted);
    },

    findById: function (id) {
        const items = readDataFromFile(this.filename);
        return items.find(c => c._id === id && !c.isDeleted);
    },

    findBySlug: function (slug) {
        const items = readDataFromFile(this.filename);
        return items.find(c => c.slug === slug && !c.isDeleted);
    },

    create: function (name, slug, description = '', images = []) {
        const items = readDataFromFile(this.filename);
        const newCategory = {
            _id: generateId(),
            name: name,
            slug: slug,
            description: description,
            images: images.length ? images : ["https://smithcodistributing.com/wp-content/themes/hello-elementor/assets/default_product.png"],
            isDeleted: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        items.push(newCategory);
        writeDataToFile(this.filename, items);
        return newCategory;
    },

    update: function (id, updates) {
        const items = readDataFromFile(this.filename);
        const index = items.findIndex(c => c._id === id);
        if (index !== -1) {
            items[index] = { ...items[index], ...updates, updatedAt: new Date().toISOString() };
            writeDataToFile(this.filename, items);
            return items[index];
        }
        return null;
    },

    delete: function (id) {
        return this.update(id, { isDeleted: true });
    }
};

// Quản lý Products
const ProductManager = {
    filename: 'products.json',

    findAll: function () {
        return readDataFromFile(this.filename).filter(p => !p.isDeleted);
    },

    findById: function (id) {
        const items = readDataFromFile(this.filename);
        const product = items.find(p => p._id === id && !p.isDeleted);
        if (product) {
            const category = CategoryManager.findById(product.category);
            return { ...product, category };
        }
        return null;
    },

    findBySlug: function (slug) {
        const items = readDataFromFile(this.filename);
        return items.find(p => p.slug === slug && !p.isDeleted);
    },

    create: function (title, slug, price, description, categoryId, images = []) {
        const items = readDataFromFile(this.filename);
        const newProduct = {
            _id: generateId(),
            title: title,
            slug: slug,
            price: price,
            description: description,
            category: categoryId,
            images: images.length ? images : ["https://smithcodistributing.com/wp-content/themes/hello-elementor/assets/default_product.png"],
            isDeleted: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        items.push(newProduct);
        writeDataToFile(this.filename, items);
        return newProduct;
    },

    update: function (id, updates) {
        const items = readDataFromFile(this.filename);
        const index = items.findIndex(p => p._id === id);
        if (index !== -1) {
            items[index] = { ...items[index], ...updates, updatedAt: new Date().toISOString() };
            writeDataToFile(this.filename, items);
            return items[index];
        }
        return null;
    },

    delete: function (id) {
        return this.update(id, { isDeleted: true });
    }
};

// Quản lý Users
const UserManager = {
    filename: 'users.json',

    findAll: function () {
        return readDataFromFile(this.filename).filter(u => !u.isDeleted);
    },

    findById: function (id) {
        const items = readDataFromFile(this.filename);
        return items.find(u => u._id === id && !u.isDeleted);
    },

    findByUsername: function (username) {
        const items = readDataFromFile(this.filename);
        return items.find(u => u.username === username && !u.isDeleted);
    },

    findByEmail: function (email) {
        const items = readDataFromFile(this.filename);
        return items.find(u => u.email === email && !u.isDeleted);
    },

    create: function (username, password, email, fullName, role, avatarUrl = null, status = false) {
        const items = readDataFromFile(this.filename);
        const newUser = {
            _id: generateId(),
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl || "https://i.sstatic.net/l60Hf.png",
            status: status,
            role: role,
            loginCount: 0,
            lockTime: null,
            isDeleted: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        items.push(newUser);
        writeDataToFile(this.filename, items);
        return newUser;
    },

    update: function (id, updates) {
        const items = readDataFromFile(this.filename);
        const index = items.findIndex(u => u._id === id);
        if (index !== -1) {
            items[index] = { ...items[index], ...updates, updatedAt: new Date().toISOString() };
            writeDataToFile(this.filename, items);
            return items[index];
        }
        return null;
    },

    delete: function (id) {
        return this.update(id, { isDeleted: true });
    }
};

module.exports = {
    RoleManager,
    CategoryManager,
    ProductManager,
    UserManager,
    generateId
};
