import userModel from '../Models/userModel.js'
import jwt from 'jsonwebtoken'
export const getUserData = async (req,res) => {
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

        res.json({success:true, userData:{
            name: user.name,
            isAccountVerified: user.isAccountVerified
        }})

} catch (error) {

    res.json({success:false,message:error.message})

}


}