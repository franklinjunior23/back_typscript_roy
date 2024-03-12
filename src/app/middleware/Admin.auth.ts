import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import "dotenv/config";

export async function ValidateAdminToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const tokenUser = req.header(String(process.env.VALIDATION_HEADER) || "R223_FRNXUSE20");
  if (!tokenUser)
    return res.status(401).json({ message: "Token not provided" });

  try {
    const Decoded: any = await jwt.verify(
      tokenUser,
      String(process.env.SECRET_KEY_JWT) || ""
    );
   
    if (Decoded.datos.Role.nombre === "Administrador") return next();
   
    return res.status(401).json({ message: "Acceso denegado. No tienes el rol requerido para esta acción." });
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Acceso denegado. No tienes el rol requerido para esta acción." });

  }
}
