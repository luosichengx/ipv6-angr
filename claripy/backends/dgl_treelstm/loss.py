import torch
import torch.nn as nn
import torch.nn.functional as func

class myLoss(nn.Module):
    def __init__(self,parameters):
        self.params = self.parameters

    def forward(self):
        loss = cal_loss(self.params)
        return loss