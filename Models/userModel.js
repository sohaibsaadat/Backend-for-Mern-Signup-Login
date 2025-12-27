import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{type:String, require:true},
    email:{type:String, require:true, unique:true},
    password:{type:String, require:true},
    verifyOtp:{type:String, default:""},
    verifyOtpExpireAt:{type:Number, default:0},
    isAccountVerified:{type:Boolean, default:false},
    resetOtp:{type:String, default:""},
    resetOtpExpireAt:{type:String, default:0},
    resetToken: { type: String },
    resetTokenExpireAt: { type: Number }


})

const userModel = mongoose.models.user ||  mongoose.model('user',userSchema)

export default userModel