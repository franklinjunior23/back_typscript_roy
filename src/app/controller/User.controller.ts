import { Model, Op } from "sequelize";
import Empresa from "../models/Empresa";
import { Request, Response } from "express";
import Sucursal from "../models/Sucursales";
import Users from "../models/Users";
import Dispositivo from "../models/Dispositvo";

export const GetUsersByEmpresaAndSucursal = async (
  req: Request,
  res: Response
) => {
  try {
    const { empresa, sucursal } = req.params;

    const UserData: any = await Users.findAll({
      include: [
        {
          model: Sucursal,
          where: {
            nombre: { [Op.eq]: sucursal },
          },
          include: [
            {
              model: Empresa,
              where: {
                nombre: { [Op.eq]: empresa },
              },
            },
          ],
        },
        {
          model: Dispositivo,
        },
      ],
    });
    return res.json(UserData);
  } catch (error) {
    res.json(error);
  }
};
export const CreateUserBySucursal = async (req: Request, res: Response) => {
  try {
    const { empresa, sucursal } = req.params;
    const datoUser = req.body;
    const resSuc: any = await Sucursal.findOne({
      where: {
        nombre: {
          [Op.eq]: sucursal,
        },
      },
      include: [
        {
          model: Empresa,
          where: {
            nombre: { [Op.eq]: empresa },
          },
        },
      ],
    });
    if (resSuc) {
      const CreateUser = await Users.create({
        ...datoUser,
        IdSucursal: resSuc?.id,
      });

      res.json({ create: true });
    }
    return res.json({ create: false });
  } catch (error) {}
};

export const GetUserById = async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const resp = await Users.findOne({
      where: {
        id,
      },
      include: [
        {
          model: Dispositivo,
        },
      ],
    });
    if (!resp) return res.json({ where: false });
    res.json({ where: true, resp });
  } catch (error) {
    res.json(500).json(error);
  }
};

export const DeleteUserById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const Exist = await Users.findOne({
      where: { id },
    });
    console.log(id);
    if (Exist) {
      await Users.destroy({
        where: {
          id,
        },
      });
      return res.json({ search: true });
    }
    res.json({ search: false });
  } catch (error) {
    console.log(error);
  }
};
export const UpdateUserById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const NewDatos = req.body;
    const Exist: any = await Users.findByPk(id);
    const cambios: any = {};
    console.log(id)
    if (!Exist) return res.json({ search: false });

    for (const CamposUpdate in NewDatos) {
      if (Exist[CamposUpdate] !== NewDatos[CamposUpdate]) {
        cambios[CamposUpdate] = NewDatos[CamposUpdate];
      }
    }
    await Exist.update(cambios);

    res.json({ search: true, data: Exist, cambios });
  } catch (error) {}
};
export const GetsUserDisp = async (req: Request, res: Response) => {
  try {
    const { empresa, sucursal } = req.query;
    console.log("llego")
    const resp = await Users.findAll({
      include: [
        {
          model: Sucursal,
          where: {
            nombre: sucursal,
          },
          include: [
            {
              model: Empresa,
              where: {
                nombre: empresa,
              },
            },
          ],
        },
        {
            model:Dispositivo
        }
      ],
    });
    res.json(resp);
  } catch (error) {
    console.log(error);
  }
};
