import CreateNotify from "../utils/CreateNotify";
import { Users, Sucursales, Empresa, Ticket, Administradores } from "../models";
import { Request, Response } from "express";
import { DateTime } from "luxon";

//empresasss
export const GetEmpresas = async (req: Request, res: Response) => {
  try {

    const search = await Empresa.findAll({
      attributes: ["id", "nombre", "lugar"],
      include: [{ model: Sucursales, attributes: ["id", "nombre"] }],
    });
    const { count: CountEmpresas } = await Empresa.findAndCountAll();
    const { count: CountSucursales } = await Sucursales.findAndCountAll();
    const { count: CountUsers } = await Users.findAndCountAll();
    const { count: Countickets } = await Ticket.findAndCountAll();

    const DataUser = await Administradores.findAll({
      attributes: ["nombre", "apellido", "isActive", "updatedAt"],
    });
    const details = {
      Empresas: CountEmpresas,
      Sucursales: CountSucursales,
      Usuarios: CountUsers,
      Tickets: Countickets,
    };
    res.json({ data: search, details, ListUsers: DataUser });
  } catch (error) {
    console.log(error);
    res.json({
      empresas: false,
      msg: "error en el servidor comunique con el soporte",
    });
  }
};

export const CreateEmpresa = async (req: any, res: Response) => {
  try {
    const { nombre, lugar } = req.body;
    if (nombre && lugar) {
      const cret = await Empresa.create({
        nombre,
        lugar,
      });
      console.log(req.User);
      await CreateNotify(
        `Se ha creado una nueva empresa con el nombre "${nombre}"`,
        req.User?.nombre,
        req.User?.id
      );
      return res.json({ create: true, cret });
    }
    return res
      .status(201)
      .json({ create: false, msg: "Complete los parametros requeridos" });
  } catch (error) {
    res
      .status(501)
      .json({ error: true, msg: "conectese con el administrador EMPCONTROLL" });
  }
};
export const DeleteEmpresa = async (req: Request, res: Response) => {
  try {
    const idEmpresa = req.params.id;

    const resp = await Empresa.update(
      {deletedAt: DateTime.local().setZone("America/Lima").toISO()},
      {where: {id: idEmpresa}}
    );
    if (!resp) {
      return res.json({ delete: false, });
    }
    res.json({ delete: true,message:"Empresa Eliminada" });
  } catch (error:any) {
    res.status(404).json({
      status:404,
      message:error?.message
    })
  }
};

//sucursales
