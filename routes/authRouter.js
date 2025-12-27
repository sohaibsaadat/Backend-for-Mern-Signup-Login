import express from 'express'
import { isAuthenticated, login, logout, register, resetPassword, sentResetOtp, verifyEmail, verifyOtp, verifyResetOtp } from '../controllers/authController.js'

const authRouter = express.Router();


authRouter.post('/register',register)
authRouter.post('/login',login)
authRouter.post('/logout',logout)
authRouter.post('/verify-account',verifyEmail)
authRouter.post('/sent-verify-otp',verifyOtp)
authRouter.get('/is-auth',isAuthenticated)
authRouter.post('/sent-reset-otp',sentResetOtp)
authRouter.post('/verify-reset-otp',verifyResetOtp)
authRouter.post('/reset-password',resetPassword)

export default authRouter