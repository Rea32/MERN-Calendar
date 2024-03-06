const { response } = require('express');
const Usuario = require('../models/User');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt')


const crearUsuario = async( req, res = response ) =>{

    const { email, password }= req.body;
    try {
        let usuario = await Usuario.findOne({ email });
        
        if ( usuario ){
            return res.status(400).json({
                ok: false,
                msg: "Un usuario existe con ese correo"
            })
        }
        usuario = new Usuario(req.body);

        //Encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync( password, salt );

        await usuario.save();

        //Generar JsonWebToken
        const token = await generarJWT(usuario._id, usuario.name);

        res.status(201).json({
            ok: true,
            uid: usuario._id,
            name: usuario.name,
            token
        });
    } catch (error) {
        console.log(error)
        res.status(500).json({
            ok: false,
            msg: 'Por favor, hable con el administrador'
        })
        
    }

};

const loginUsuario = async ( req, res = response ) =>{

    const { email, password }= req.body;

    try {
        let usuario = await Usuario.findOne({ email });
        
        if ( !usuario ){
            return res.status(400).json({
                ok: false,
                msg: "El usuario no es correcto con ese mail"
            });
        }

        //Confirmar los passwords
        const validPassword = bcrypt.compareSync( password, usuario.password );

        if ( !validPassword ){
            return res.status(400).json({
                ok: false, 
                msg: 'Contraseña incorrecta'
            });
        }

        //Generar JsonWebToken
        const token = await generarJWT(usuario._id, usuario.name);

        res.json({
            ok: true,
            uid: usuario._id,
            name: usuario.name,
            token

        })
        
    } catch (error) {
        console.log(error)
        res.status(500).json({
            ok: false,
            msg: 'Por favor, hable con el administrador'
        })
        
    }

};

const revalidarToken = async ( req, res ) =>{
    const { uid, name }= req;

    //Generar un nuevo JWT y retornarlo en esta peticion

    const token = await generarJWT(uid, name);

    res.json({
        ok: true,
        uid,
        name,
        token
    })
};

module.exports = { 
    crearUsuario, 
    loginUsuario, 
    revalidarToken 
};