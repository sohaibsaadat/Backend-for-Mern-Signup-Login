import userModel from "../Models/userModel.js";
import bcrypt from 'bcryptjs'
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";
import crypto from "crypto";


export const register = async (req, res) => {

    const { name, email, password } = req.body

    if (!name || !email || !password) {
        return res.json({ succes: false, message: "Missing Details" })
    }



    try {
        const exsistingUser = await userModel.findOne({ email })

        if (exsistingUser) {
            return res.json({ success: false, message: "User Already Exsist" })
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({
            name,
            email,
            password: hashedPassword,
        })
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" })

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })


        //Sending Welcome Email

        const mailOptions = {

            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome To Mern Auth System',
            text: `Hi ${name}. Your account has been created with email: ${email}`
        }

        await transporter.sendMail(mailOptions)

        return res.json({ success: true ,message:"OTP Sent To Your Email"})


    } catch (error) {
        res.json({ succes: false, message: error.message })
    }

}

export const login = async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.json({ succes: false, message: "Email And Password Are Required" })
    }

    try {

        const user = await userModel.findOne({ email })

        if (!user) {
            return res.json({ success: false, message: "User Did Not Exsist" })
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            return res.json({ success: false, message: "Incorrect Password" })
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" })

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        return res.json({ success: true, message: "Logged In" })

    } catch (error) {
        res.json({ succes: false, message: error.message })

    }
}


export const logout = async (req, res) => {
    try {

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({ success: true, message: "Logged Out" })

    } catch (error) {

        res.json({ succes: false, message: error.message })

    }
}

export const verifyOtp = async (req, res) => {
    try {
        const { token } = req.cookies;

        if (!token) {
            return res.json({ success: false, message: "Not Authorized. Login Again" });
        }

        let id;
        try {
            const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
            if (tokenDecode.id) {
                id = tokenDecode.id;
            } else {
                return res.json({ success: false, message: "Not Authorized. Login Again" });
            }
        } catch (error) {
            return res.json({ success: false, message: error.message });
        }

        const user = await userModel.findById(id);

        if (!user) {
            return res.json({ success: false, message: "User Not Found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account Already Verified" });
        }

const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification',
            text: `Hi ${user.name}. Your OTP for the verification is: ${otp}. Please Do not Share it with anyone.`,
        };

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: "OTP Sent Successfully" });

    } catch (error) {
        console.error("Error in verifyOtp:", error);
        return res.json({ success: false, message: error.message });
    }
};


export const verifyEmail = async (req, res) => {

    const { otp } = req.body


    const { token } = req.cookies

    if (!token) {
        return res.json({ success: false, message: "Not Authorized. Login Again" });
    }

    let id;

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        if (tokenDecode.id) {
            id = tokenDecode.id;
        } else {
            return res.json({ success: false, message: "Not Authorized. Login Again" });
        }
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }

    if (!id || !otp) {

        return res.json({ success: false, message: "Missing Details" })

    }


    try {

        const user = await userModel.findById(id)

        if (!user) {

            return res.json({ success: false, message: "User Not Found" })

        }

        if (user.verifyOtp === "" || user.verifyOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" })
        }


        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" })

        }


        user.isAccountVerified = true
        user.verifyOtp = ''
        user.verifyOtpExpireAt = 0


        await user.save()

        return res.json({ success: true, message: "Email Verified Successfully" })

    } catch (error) {
        res.json({ succes: false, message: error.message })

    }

}

export const isAuthenticated = async (req, res) => {
  try {
    const { token } = req.cookies;

    if (!token) {
      return res.json({ success: false, message: "Not Authenticated" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await userModel.findById(decoded.id).select("-password");
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, user }); 

  } catch (error) {
    return res.json({ success: false, message: "Invalid or expired token" });
  }
};

export const sentResetOtp = async (req, res) => {
    const { email } = req.body

    if (!email) {
        return res.json({ succes: false, message: "Email is Required " })
    }

    try {

        const user = await userModel.findOne({ email })

        if (!user) {
            return res.json({ success: false, message: "User Did Not Exsist" })
        }

const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Hi ${user.name}. Your OTP for the Password Resetting is: ${otp}. Use this OTP to proceed with resetting your passowrd Please Do not Share it with anyone.`,
        };

        await transporter.sendMail(mailOptions);

        return res.json({ succes: true, message: "OTP Sent To Your Email For Password Reset" })
    } catch (error) {

        return res.json({ success: false, message: error.message });

    }

}

    export const verifyResetOtp = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    if (!user.resetOtp || user.resetOtpExpireAt < Date.now())
      return res.status(400).json({ success: false, message: "OTP expired or invalid" });

    if (user.resetOtp !== otp) return res.status(400).json({ success: false, message: "Invalid OTP" });

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpireAt = Date.now() + 10 * 60 * 1000;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "OTP verified", resetToken });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};
export const resetPassword = async (req, res) => {
  const { resetToken, newPassword } = req.body;
  try {
    const user = await userModel.findOne({
      resetToken,
      resetTokenExpireAt: { $gt: Date.now() }
    });
    if (!user) return res.status(400).json({ success: false, message: "Invalid or expired reset token" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = "";
    user.resetTokenExpireAt = 0;
    await user.save();

    return res.json({ success: true, message: "Password reset successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};



