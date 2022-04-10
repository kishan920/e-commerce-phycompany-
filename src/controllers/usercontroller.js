const userModel = require('../models/userModel')
const validator = require('../utils/validator')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const client = require('twilio')('AC9890eb4f3992818a68428c18f9aa19f7', '0a51f17a2ea78c45fa933afb8f4b5f6a');
function verifiedMsg( phone)
{
    client.messages.create({
        body: 'Hello from Node',
        to: `${phone}`,
        from: `${phone}`
     }).then(message => console.log(message))
       // here you can implement your fallback code
       .catch(error => console.log(error))
}

//creating user by validating every details.
const userCreation = async(req, res) => {
    try {
        let requestBody = req.body;
        let {
            fname,
            lname,
            email,
            phone,
            password,
            address
        } = requestBody

        //validation starts
        if (!validator.isValidRequestBody(requestBody)) {
            return res.status(400).send({ status: false, message: "please provide valid request body" })
        }
        if (!validator.isValid(fname)) {
            return res.status(400).send({ status: false, message: "fname is required" })
        }
        if (!validator.isValid(lname)) {
            return res.status(400).send({ status: false, message: "lname is required" })
        }
        if (!validator.isValid(email)) {
            return res.status(400).send({ status: false, message: "email is required" })
        }

        //searching email in DB to maintain its uniqueness
        const isEmailAleadyUsed = await userModel.findOne({ email })
        if (isEmailAleadyUsed) {
            return res.status(400).send({
                status: false,
                message: `${email} is already in use. Please try another email Id.`
            })
        }

        //validating email using RegEx.
        if (!/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email))
            return res.status(400).send({ status: false, message: "Invalid Email id." })

        
        if (!validator.isValid(phone)) {
            return res.status(400).send({ status: false, message: "phone number is required" })
        }

        //searching phone in DB to maintain its uniqueness
        const isPhoneAleadyUsed = await userModel.findOne({ phone })
        if (isPhoneAleadyUsed) {
            return res.status(400).send({
                status: false,
                message: `${phone} is already in use, Please try a new phone number.`
            })
        }

        //validating phone number of 10 digits only.
        if (!(/^(?:(?:\+|0{0,2})91(\s*[\-]\s*)?|[0]?)?[6789]\d{9}$/.test(phone))) return res.status(400).send({ status: false, message: "Phone number must be a valid Indian number." })
         if(!verifiedMsg(phone))
         {
         return res.status(400).send({ status: false, message: "Contact no is not verify" })
         }
        if (!validator.isValid(password)) {
            return res.status(400).send({ status: false, message: "password is required" })
        }
        if (password.length < 8 || password.length > 15) {
            return res.status(400).send({ status: false, message: "Password must be of 8-15 letters." })
        }
        if (!validator.isValid(address)) {
            return res.status(400).send({ status: false, message: "Address is required" })
        }
        //shipping address validation
        if (address.shipping) {
            if (address.shipping.street) {
                if (!validator.isValidRequestBody(address.shipping.street)) {
                    return res.status(400).send({
                        status: false,
                        message: "Shipping address's Street Required"
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: " Invalid request parameters. Shipping address's street cannot be empty" })
            }

            if (address.shipping.city) {
                if (!validator.isValidRequestBody(address.shipping.city)) {
                    return res.status(400).send({
                        status: false,
                        message: "Shipping address city Required"
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: "Invalid request parameters. Shipping address's city cannot be empty" })
            }
            if (address.shipping.pincode) {
                if (!validator.isValidRequestBody(address.shipping.pincode)) {
                    return res.status(400).send({
                        status: false,
                        message: "Shipping address's pincode Required"
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: "Invalid request parameters. Shipping address's pincode cannot be empty" })
            }
        } else {
            return res.status(400).send({ status: false, message: "Shipping address cannot be empty." })
        }
        // Billing Address validation
        if (address.billing) {
            if (address.billing.street) {
                if (!validator.isValidRequestBody(address.billing.street)) {
                    return res.status(400).send({
                        status: false,
                        message: "Billing address's Street Required"
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: " Invalid request parameters. Billing address's street cannot be empty" })
            }
            if (address.billing.city) {
                if (!validator.isValidRequestBody(address.billing.city)) {
                    return res.status(400).send({
                        status: false,
                        message: "Billing address's city Required"
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: "Invalid request parameters. Billing address's city cannot be empty" })
            }
            if (address.billing.pincode) {
                if (!validator.isValidRequestBody(address.billing.pincode)) {
                    return res.status(400).send({
                        status: false,
                        message: "Billing address's pincode Required "
                    })
                }
            } else {
                return res.status(400).send({ status: false, message: "Invalid request parameters. Billing address's pincode cannot be empty" })
            }
        } else {
            return res.status(400).send({ status: false, message: "Billing address cannot be empty." })
        }
        //validation ends

       
        //object destructuring for response body.
        userData = {
            fname,
            lname,
            email,
            phone,
            password: encryptedPassword,
            address
        }

        const saveUserData = await userModel.create(userData);
        return res
            .status(201)
            .send({
                status: true,
                message: "user created successfully.",
                data: saveUserData
            });
    } catch (err) {
        return res.status(500).send({
            status: false,
            message: "Error is : " + err
        })
    }
}
//user login by validating the email and password.
const userLogin = async function(req, res) {
    try {
        const requestBody = req.body;

        // Extract params
        const { email, password } = requestBody;

        // Validation starts
        if (!validator.isValidRequestBody(requestBody)) {
            return res.status(400).send({ status: false, message: 'Invalid request parameters. Please provide login details' })
        }
        if (!validator.isValid(requestBody.email)) {
            return res.status(400).send({ status: false, message: 'Email Id is required' })
        }

        if (!validator.isValid(requestBody.password)) {
            return res.status(400).send({ status: false, message: 'Password is required' })
        }
        // Validation ends

        //finding user's details in DB to verify the credentials.
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(401).send({ status: false, message: `Login failed! email id is incorrect.` });
        }

        let hashedPassword = user.password
        const encryptedPassword = await bcrypt.compare(password, hashedPassword) //converting normal password to hashed value to match it with DB's entry by using compare function.

        if (!encryptedPassword) return res.status(401).send({ status: false, message: `Login failed! password is incorrect.` });
       //Creating JWT token through userId. 
       const userId = user._id
       const token = await jwt.sign({
           userId: userId,
           iat: Math.floor(Date.now() / 1000),   //time of issuing the token.
           exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 7   //setting token expiry time limit.
       }, 'secret');
    
        return res.status(200).send({
            status: true,
            message: `user login successfull `,
            data: {
                userId,
                token
            }
        });
    } catch (err) {
        return res.status(500).send({ status: false, message: err.message });
    }
}
module.exports = {
          userCreation,
          userLogin
        }