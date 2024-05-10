import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";
export const register = async (req, res) => {
  const { username, email, password } = req.body;

  try {

    //hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword)

    //create a new user and save to db
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword
      }
    })

    res.status(201).json({ message: "User created successfully!" })
  } catch (err) {
    console.log(err)
    res.status(500).json({ message: "Failed to save user data" })
  }
}

export const login = async (req, res) => {
  const { username, password } = req.body;
  try {

    //check if user exist

    const user = await prisma.user.findUnique({
      where: { username }
    })
    console.log(user)
    if (!user) return res.status(401).json({ message: "Invalid credentials!" })

    //check if the password is correct

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: "Invalid credentials!" })

    //generate cookie token and send to the user
    // res.setHeader("Set-Cookie", "test=" + "myValue").json("success")
    const age = 1000 * 60 * 60 * 24 * 7;
    const token = jwt.sign({
      id: user.id
    },
      process.env.JWT_SECRET_KEy,
      { expiresIn: age })

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: age,
      // secure:true
    }).status(200).json({ message: "Login successful" })
  } catch (err) {
    console.log(err)
    res.status(500).json({ message: "Failed to login" })
  }
}

export const logout = (req, res) => {
  //db operstions
  res.clearCookie("token").status(200).json({ message: "Logout successful" })
}