const express = require("express");
const multer = require("multer");

const app = express();

const PORT = 3000;

// EJS Template Engine
app.set("view engine", "ejs");

// Multer Configuration
const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storage });

// Static Files
app.use(express.static("public"));

// Middleware
app.use((req, res, next) => {
    console.log("Middleware Executed");
    next();
});

// Home Route + EJS
app.get("/", (req, res) => {
    res.render("index", {
        name: "Somesh"
    });
});

// About Route
app.get("/about", (req, res) => {
    res.render("about");
});

// Route Parameter
app.get("/student/:id", (req, res) => {
    res.render("student", {
        id: req.params.id
    });
});

// File Upload
app.post("/upload", upload.single("photo"), (req, res) => {
    res.send("File Uploaded Successfully");
});

// Test Error Route
app.get("/error", (req, res, next) => {
    const error = new Error("Something went wrong");
    next(error);
});

// 404 Error Handler
app.use((req, res) => {
    res.status(404).send("Page Not Found");
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err.message);

    res.status(500).render("error");
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});